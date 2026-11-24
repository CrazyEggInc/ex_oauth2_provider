defmodule ExOauth2Provider.Token.ConcurrencyTest do
  use ExUnit.Case, async: false

  alias Dummy.{
    OauthAccessGrants.OauthAccessGrant,
    OauthAccessTokens.OauthAccessToken,
    OauthApplications.OauthApplication,
    Repo,
    Users.User
  }

  alias Ecto.Adapters.SQL.Sandbox
  alias ExOauth2Provider.{Token, Token.RefreshToken}
  alias ExOauth2Provider.Test.Fixtures

  setup do
    Sandbox.mode(Repo, :auto)

    on_exit(fn ->
      Repo.delete_all(OauthAccessToken)
      Repo.delete_all(OauthAccessGrant)
      Repo.delete_all(OauthApplication)
      Repo.delete_all(User)
      Sandbox.mode(Repo, :manual)
    end)

    user = Fixtures.resource_owner()
    application = Fixtures.application(resource_owner: user, uid: "conc_client", secret: "secret")

    {:ok, %{user: user, application: application}}
  end

  test "concurrent authorization_code exchanges succeed at most once", %{
    user: user,
    application: application
  } do
    redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
    grant = Fixtures.access_grant(application, user, "concurrent_code_1", redirect_uri)

    request = %{
      "client_id" => application.uid,
      "client_secret" => application.secret,
      "code" => grant.token,
      "grant_type" => "authorization_code",
      "redirect_uri" => redirect_uri
    }

    results = run_concurrently(4, fn -> Token.grant(request, otp_app: :ex_oauth2_provider) end)

    successes = Enum.filter(results, &match?({:ok, _}, &1))
    failures = Enum.filter(results, &match?({:error, %{error: :invalid_grant}, _}, &1))

    assert length(successes) == 1
    assert length(failures) == 3
  end

  test "concurrent refresh_token rotations succeed at most once", %{
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

    results =
      run_concurrently(4, fn ->
        RefreshToken.grant(request,
          otp_app: :ex_oauth2_provider,
          revoke_refresh_token_on_use: true
        )
      end)

    successes = Enum.filter(results, &match?({:ok, _}, &1))
    failures = Enum.filter(results, &match?({:error, %{error: :invalid_request}, _}, &1))

    assert length(successes) == 1
    assert length(failures) == 3
  end

  defp run_concurrently(count, fun) do
    parent = self()

    tasks =
      for _ <- 1..count do
        Task.async(fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> fun.()
          end
        end)
      end

    for _ <- 1..count do
      receive do
        {:ready, pid} -> pid
      end
    end
    |> Enum.each(&send(&1, :go))

    Task.await_many(tasks, 10_000)
  end
end
