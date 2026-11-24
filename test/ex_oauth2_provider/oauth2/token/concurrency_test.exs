defmodule ExOauth2Provider.Token.ConcurrencyTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Dummy.{
    OauthAccessGrants.OauthAccessGrant,
    OauthAccessTokens.OauthAccessToken,
    OauthApplications.OauthApplication,
    Repo,
    Users.User
  }

  alias Ecto.Adapters.SQL.Sandbox
  alias ExOauth2Provider.{AccessTokens, Token, Token.RefreshToken}
  alias ExOauth2Provider.Test.Fixtures

  setup do
    Sandbox.mode(Repo, :auto)

    user =
      Fixtures.resource_owner(email: "conc_#{System.unique_integer([:positive])}@example.com")

    application =
      Fixtures.application(
        resource_owner: user,
        uid: "conc_client_#{System.unique_integer([:positive])}",
        secret: "secret"
      )

    on_exit(fn ->
      Repo.delete_all(from(t in OauthAccessToken, where: t.application_id == ^application.id))
      Repo.delete_all(from(g in OauthAccessGrant, where: g.application_id == ^application.id))
      Repo.delete_all(from(a in OauthApplication, where: a.id == ^application.id))
      Repo.delete_all(from(u in User, where: u.id == ^user.id))
      Sandbox.mode(Repo, :manual)
    end)

    {:ok, %{user: user, application: application}}
  end

  test "concurrent authorization_code exchanges inside outer transactions succeed once without rollback crash",
       %{
         user: user,
         application: application
       } do
    redirect_uri = "urn:ietf:wg:oauth:2.0:oob"

    grant =
      Fixtures.access_grant(
        application,
        user,
        "concurrent_code_#{System.unique_integer([:positive])}",
        redirect_uri
      )

    request = %{
      "client_id" => application.uid,
      "client_secret" => application.secret,
      "code" => grant.token,
      "grant_type" => "authorization_code",
      "redirect_uri" => redirect_uri
    }

    # Hold a FOR UPDATE lock on the grant row so both tasks pass load_active_access_grant
    # (plain SELECT is not blocked) and block together on the atomic UPDATE inside the transaction.
    {locker, release_lock} = lock_row(OauthAccessGrant, grant.id)

    tasks =
      for _ <- 1..2 do
        Task.async(fn ->
          Repo.transaction(fn ->
            Token.grant(request, otp_app: :ex_oauth2_provider)
          end)
        end)
      end

    wait_for_blocked_locks("oauth_access_grants", 2)
    release_lock.()
    Task.await(locker, 5_000)

    results = Task.await_many(tasks, 10_000)

    # Every outer Repo.transaction must return {:ok, result}, never {:error, :rollback}
    assert Enum.all?(results, &match?({:ok, _}, &1)),
           "unexpected outer tx results: #{inspect(results)}"

    inner = Enum.map(results, fn {:ok, res} -> res end)
    assert Enum.count(inner, &match?({:ok, _}, &1)) == 1

    assert Enum.count(
             inner,
             &match?({:error, %{error: :invalid_grant}, :unprocessable_entity}, &1)
           ) == 1
  end

  test "concurrent refresh_token rotations inside outer transactions succeed once without rollback crash",
       %{
         user: user,
         application: application
       } do
    access_token =
      Fixtures.access_token(
        resource_owner: user,
        application: application,
        use_refresh_token: true,
        scopes: "read"
      )

    request = %{
      "client_id" => application.uid,
      "client_secret" => application.secret,
      "grant_type" => "refresh_token",
      "refresh_token" => access_token.refresh_token
    }

    {locker, release_lock} = lock_row(OauthAccessToken, access_token.id)

    tasks =
      for _ <- 1..2 do
        Task.async(fn ->
          Repo.transaction(fn ->
            RefreshToken.grant(request,
              otp_app: :ex_oauth2_provider,
              revoke_refresh_token_on_use: true
            )
          end)
        end)
      end

    wait_for_blocked_locks("oauth_access_tokens", 2)
    release_lock.()
    Task.await(locker, 5_000)

    results = Task.await_many(tasks, 10_000)

    assert Enum.all?(results, &match?({:ok, _}, &1)),
           "unexpected outer tx results: #{inspect(results)}"

    inner = Enum.map(results, fn {:ok, res} -> res end)
    assert Enum.count(inner, &match?({:ok, _}, &1)) == 1
    assert Enum.count(inner, &match?({:error, %{error: :invalid_request}, :bad_request}, &1)) == 1
  end

  test "refresh_token with revoke_refresh_token_on_use: false refuses token revoked mid-flight",
       %{
         user: user,
         application: application
       } do
    access_token =
      Fixtures.access_token(
        resource_owner: user,
        application: application,
        use_refresh_token: true,
        scopes: "read"
      )

    request = %{
      "client_id" => application.uid,
      "client_secret" => application.secret,
      "grant_type" => "refresh_token",
      "refresh_token" => access_token.refresh_token
    }

    # Hold FOR UPDATE lock, wait for refresh to pass initial SELECT and block on FOR SHARE,
    # then revoke and commit in the locker transaction.
    parent = self()

    locker =
      Task.async(fn ->
        Repo.transaction(fn ->
          token =
            from(t in OauthAccessToken, where: t.id == ^access_token.id, lock: "FOR UPDATE")
            |> Repo.one!()

          send(parent, :locked)

          receive do
            :revoke_and_commit ->
              {:ok, _} = AccessTokens.revoke(token, otp_app: :ex_oauth2_provider)
          end
        end)
      end)

    assert_receive :locked, 5_000

    refresh_task =
      Task.async(fn ->
        Repo.transaction(fn ->
          RefreshToken.grant(request,
            otp_app: :ex_oauth2_provider,
            revoke_refresh_token_on_use: false
          )
        end)
      end)

    wait_for_blocked_locks("oauth_access_tokens", 1)
    send(locker.pid, :revoke_and_commit)
    Task.await(locker, 5_000)

    assert {:ok, {:error, %{error: :invalid_request}, :bad_request}} =
             Task.await(refresh_task, 10_000)
  end

  test "transaction-time owner deletion during authorization_code exchange returns invalid_grant without rollback crash",
       %{
         application: application
       } do
    victim =
      Fixtures.resource_owner(email: "victim_#{System.unique_integer([:positive])}@example.com")

    redirect_uri = "urn:ietf:wg:oauth:2.0:oob"

    grant =
      Fixtures.access_grant(
        application,
        victim,
        "victim_code_#{System.unique_integer([:positive])}",
        redirect_uri
      )

    request = %{
      "client_id" => application.uid,
      "client_secret" => application.secret,
      "code" => grant.token,
      "grant_type" => "authorization_code",
      "redirect_uri" => redirect_uri
    }

    # Drop FK temporarily to simulate ce's schema (no FK) and restore in on_exit
    Repo.query!(
      "ALTER TABLE oauth_access_grants DROP CONSTRAINT IF EXISTS oauth_access_grants_resource_owner_id_fkey"
    )

    on_exit(fn ->
      Repo.delete_all(from(t in OauthAccessToken, where: t.resource_owner_id == ^victim.id))
      Repo.delete_all(from(g in OauthAccessGrant, where: g.id == ^grant.id))
      Repo.delete_all(from(u in User, where: u.id == ^victim.id))

      Repo.query!(
        "ALTER TABLE oauth_access_grants ADD CONSTRAINT oauth_access_grants_resource_owner_id_fkey FOREIGN KEY (resource_owner_id) REFERENCES users(id)"
      )
    end)

    parent = self()

    locker =
      Task.async(fn ->
        Repo.transaction(fn ->
          from(g in OauthAccessGrant, where: g.id == ^grant.id, lock: "FOR UPDATE") |> Repo.one!()
          send(parent, :locked)

          receive do
            :delete_owner_and_commit ->
              Repo.delete_all(from(u in User, where: u.id == ^victim.id))
          end
        end)
      end)

    assert_receive :locked, 5_000

    exchange_task =
      Task.async(fn ->
        Repo.transaction(fn ->
          Token.grant(request, otp_app: :ex_oauth2_provider)
        end)
      end)

    # Task passed load_active_access_grant (preload saw victim!) and is now blocked on grant UPDATE
    wait_for_blocked_locks("oauth_access_grants", 1)
    send(locker.pid, :delete_owner_and_commit)
    Task.await(locker, 5_000)

    assert {:ok, {:error, %{error: :invalid_grant}, :unprocessable_entity}} =
             Task.await(exchange_task, 10_000)

    assert Repo.aggregate(
             from(t in OauthAccessToken, where: t.application_id == ^application.id),
             :count,
             :id
           ) == 0
  end

  defp lock_row(schema, id) do
    parent = self()

    locker =
      Task.async(fn ->
        Repo.transaction(fn ->
          from(r in schema, where: r.id == ^id, lock: "FOR UPDATE") |> Repo.one!()
          send(parent, :locked)

          receive do
            :release -> :ok
          end
        end)
      end)

    assert_receive :locked, 5_000
    {locker, fn -> send(locker.pid, :release) end}
  end

  defp wait_for_blocked_locks(_table_name, expected_count, attempts \\ 100) do
    query = """
    SELECT COUNT(*)
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND wait_event_type = 'Lock'
      AND wait_event IN ('transactionid', 'tuple')
    """

    %{rows: [[count]]} = Repo.query!(query)

    cond do
      count >= expected_count ->
        :ok

      attempts > 0 ->
        Process.sleep(10)
        wait_for_blocked_locks(nil, expected_count, attempts - 1)

      true ->
        flunk("timed out waiting for #{expected_count} blocked lock(s), got #{count}")
    end
  end
end
