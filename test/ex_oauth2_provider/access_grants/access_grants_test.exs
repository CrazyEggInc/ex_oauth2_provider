defmodule ExOauth2Provider.AccessGrantsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.AccessGrants
  alias ExOauth2Provider.Test.Fixtures
  alias Dummy.OauthAccessGrants.OauthAccessGrant

  @valid_attrs %{expires_in: 600, redirect_uri: "https://example.org/endpoint"}

  setup do
    user = Fixtures.resource_owner()

    {:ok,
     %{user: user, application: Fixtures.application(resource_owner: user, scopes: "public read")}}
  end

  test "get_active_grant_for/3", %{user: user, application: application} do
    {:ok, grant} =
      AccessGrants.create_grant(user, application, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert %OauthAccessGrant{id: id} =
             AccessGrants.get_active_grant_for(application, grant.token,
               otp_app: :ex_oauth2_provider
             )

    assert id == grant.id

    different_application = Fixtures.application(resource_owner: user, uid: "2")

    refute AccessGrants.get_active_grant_for(different_application, grant.token,
             otp_app: :ex_oauth2_provider
           )
  end

  describe "create_grant/4" do
    test "with valid attributes", %{user: user, application: application} do
      assert {:ok, %OauthAccessGrant{} = grant} =
               AccessGrants.create_grant(user, application, @valid_attrs,
                 otp_app: :ex_oauth2_provider
               )

      assert grant.resource_owner == user
      assert grant.application == application
      assert grant.scopes == "public"
    end

    test "adds random token", %{user: user, application: application} do
      {:ok, grant} =
        AccessGrants.create_grant(user, application, @valid_attrs, otp_app: :ex_oauth2_provider)

      {:ok, grant2} =
        AccessGrants.create_grant(user, application, @valid_attrs, otp_app: :ex_oauth2_provider)

      assert grant.token != grant2.token
    end

    test "with missing expires_in", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{expires_in: nil})

      assert {:error, changeset} =
               AccessGrants.create_grant(user, application, attrs, otp_app: :ex_oauth2_provider)

      assert changeset.errors[:expires_in] == {"can't be blank", [validation: :required]}
    end

    test "with missing redirect_uri", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{redirect_uri: nil})

      assert {:error, changeset} =
               AccessGrants.create_grant(user, application, attrs, otp_app: :ex_oauth2_provider)

      assert changeset.errors[:redirect_uri] == {"can't be blank", [validation: :required]}
    end

    test "with invalid scopes", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "write"})

      assert {:error, changeset} =
               AccessGrants.create_grant(user, application, attrs, otp_app: :ex_oauth2_provider)

      assert changeset.errors[:scopes] == {"not in permitted scopes list: \"public read\"", []}
    end
  end

  describe "create_grant/4 with no application scopes" do
    setup %{user: user, application: application} do
      application = Map.merge(application, %{scopes: ""})
      %{user: user, application: application}
    end

    test "with invalid scopes", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})

      assert {:error, changeset} =
               AccessGrants.create_grant(user, application, attrs, otp_app: :ex_oauth2_provider)

      assert changeset.errors[:scopes] ==
               {"not in permitted scopes list: [\"public\", \"read\", \"write\"]", []}
    end

    test "with valid attributes", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "write"})

      assert {:ok, grant} =
               AccessGrants.create_grant(user, application, attrs, otp_app: :ex_oauth2_provider)

      assert grant.scopes == "write"
    end
  end

  test "revoke_once/2 respects loaded struct schema prefix", %{
    user: user,
    application: application
  } do
    {:ok, public_grant} =
      AccessGrants.create_grant(user, application, @valid_attrs, otp_app: :ex_oauth2_provider)

    Dummy.Repo.query!("CREATE SCHEMA tenant_revoke_test")

    Dummy.Repo.query!(
      "CREATE TABLE tenant_revoke_test.oauth_access_grants (LIKE public.oauth_access_grants INCLUDING ALL)"
    )

    Dummy.Repo.query!(
      "INSERT INTO tenant_revoke_test.oauth_access_grants SELECT * FROM public.oauth_access_grants WHERE id = $1",
      [public_grant.id]
    )

    tenant_grant =
      Dummy.Repo.get!(OauthAccessGrant, public_grant.id, prefix: "tenant_revoke_test")

    assert {:ok, revoked} = AccessGrants.revoke_once(tenant_grant, otp_app: :ex_oauth2_provider)
    assert revoked.revoked_at

    reloaded_public = Dummy.Repo.get!(OauthAccessGrant, public_grant.id)

    reloaded_tenant =
      Dummy.Repo.get!(OauthAccessGrant, public_grant.id, prefix: "tenant_revoke_test")

    assert is_nil(reloaded_public.revoked_at)
    refute is_nil(reloaded_tenant.revoked_at)
  end
end
