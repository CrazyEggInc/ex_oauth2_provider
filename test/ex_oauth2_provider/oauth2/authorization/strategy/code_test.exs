defmodule ExOauth2Provider.Authorization.CodeTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.{Authorization, Config, Scopes}
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias Dummy.{OauthAccessGrants.OauthAccessGrant, Repo}

  @client_id "Jf5rM8hQBc"
  @valid_request %{
    "client_id" => @client_id,
    "response_type" => "code",
    "scope" => "app:read app:write"
  }
  @invalid_request %{
    error: :invalid_request,
    error_description:
      "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
  }
  @invalid_client %{
    error: :invalid_client,
    error_description:
      "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
  }
  @invalid_scope %{
    error: :invalid_scope,
    error_description: "The requested scope is invalid, unknown, or malformed."
  }
  @invalid_redirect_uri %{
    error: :invalid_redirect_uri,
    error_description: "The redirect uri included is not valid."
  }
  @access_denied %{
    error: :access_denied,
    error_description: "The resource owner or authorization server denied the request."
  }

  setup do
    resource_owner = Fixtures.resource_owner()
    application = Fixtures.application(uid: @client_id, scopes: "app:read app:write")
    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  test "#preauthorize/3 error when no resource owner" do
    assert Authorization.preauthorize(nil, @valid_request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#preauthorize/3 does not redirect to unregistered redirect_uri when no resource owner", %{
    application: application
  } do
    QueryHelpers.change!(application, redirect_uri: "https://example.com/path")
    request = Map.put(@valid_request, "redirect_uri", "https://evil.example/phish")

    assert Authorization.preauthorize(nil, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 rejects unregistered native oob redirect_uri", %{
    resource_owner: resource_owner,
    application: application
  } do
    QueryHelpers.change!(application, redirect_uri: "https://example.com/callback")

    request = Map.put(@valid_request, "redirect_uri", "urn:ietf:wg:oauth:2.0:oob")

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_redirect_uri, :unprocessable_entity}
  end

  describe "PKCE validation" do
    @valid_verifier String.duplicate("a", 43)
    @valid_challenge Base.url_encode64(:crypto.hash(:sha256, @valid_verifier), padding: false)

    test "#authorize/3 requires valid S256 PKCE for public clients", %{
      resource_owner: resource_owner,
      application: application
    } do
      QueryHelpers.change!(application,
        client_type: "public",
        secret: "",
        redirect_uri: "https://example.com/callback"
      )

      base = Map.put(@valid_request, "redirect_uri", "https://example.com/callback")

      # Missing PKCE
      assert {:redirect, uri} =
               Authorization.authorize(resource_owner, base, otp_app: :ex_oauth2_provider)

      assert uri =~ "error=invalid_request"

      # Malformed challenge (too short / invalid chars)
      bad_challenge =
        Map.merge(base, %{"code_challenge" => "x", "code_challenge_method" => "S256"})

      assert {:redirect, uri} =
               Authorization.authorize(resource_owner, bad_challenge,
                 otp_app: :ex_oauth2_provider
               )

      assert uri =~ "error=invalid_request"

      # Valid S256 PKCE succeeds
      good_pkce =
        Map.merge(base, %{
          "code_challenge" => @valid_challenge,
          "code_challenge_method" => "S256"
        })

      assert {:redirect, uri} =
               Authorization.authorize(resource_owner, good_pkce, otp_app: :ex_oauth2_provider)

      assert uri =~ "code="
    end

    test "#authorize/3 rejects code_challenge_method without code_challenge for confidential client",
         %{
           resource_owner: resource_owner
         } do
      request = Map.put(@valid_request, "code_challenge_method", "plain")

      assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_request, :bad_request}

      request_s256 = Map.put(@valid_request, "code_challenge_method", "S256")

      assert Authorization.authorize(resource_owner, request_s256, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_request, :bad_request}
    end

    test "#authorize/3 rejects malformed code_challenge for confidential client", %{
      resource_owner: resource_owner
    } do
      request =
        Map.merge(@valid_request, %{
          "code_challenge" => "too-short",
          "code_challenge_method" => "S256"
        })

      assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_request, :bad_request}
    end
  end

  test "#preauthorize/3 error when no client_id", %{resource_owner: resource_owner} do
    request = Map.delete(@valid_request, "client_id")

    assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#preauthorize/3 error when invalid client", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client, :unprocessable_entity}
  end

  test "#preauthorize/3", %{resource_owner: resource_owner, application: application} do
    expected_scopes = Scopes.to_list(@valid_request["scope"])

    assert Authorization.preauthorize(resource_owner, @valid_request,
             otp_app: :ex_oauth2_provider
           ) == {:ok, application, expected_scopes}
  end

  test "#preauthorize/3 when previous access token with different application scopes", %{
    resource_owner: resource_owner,
    application: application
  } do
    access_token =
      Fixtures.access_token(
        resource_owner: resource_owner,
        application: application,
        scopes: "app:read"
      )

    expected_scopes = Scopes.to_list(@valid_request["scope"])

    assert Authorization.preauthorize(resource_owner, @valid_request,
             otp_app: :ex_oauth2_provider
           ) == {:ok, application, expected_scopes}

    QueryHelpers.change!(access_token, scopes: "app:read app:write")
    request = Map.merge(@valid_request, %{"scope" => "app:read"})
    expected_scopes = Scopes.to_list(request["scope"])

    assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:ok, application, expected_scopes}
  end

  test "#preauthorize/3 with limited scope", %{
    resource_owner: resource_owner,
    application: application
  } do
    request = Map.merge(@valid_request, %{"scope" => "app:read"})

    assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:ok, application, ["app:read"]}
  end

  test "#preauthorize/3 error when invalid scope", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"scope" => "app:invalid"})

    assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_scope, :unprocessable_entity}
  end

  describe "#preauthorize/3 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{resource_owner: resource_owner, application: application}
    end

    test "with limited server scope", %{resource_owner: resource_owner, application: application} do
      request = Map.merge(@valid_request, %{"scope" => "read"})

      assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
               {:ok, application, ["read"]}
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "invalid"})

      assert Authorization.preauthorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_scope, :unprocessable_entity}
    end
  end

  test "#preauthorize/3 when previous access token with same scopes", %{
    resource_owner: resource_owner,
    application: application
  } do
    Fixtures.access_token(
      resource_owner: resource_owner,
      application: application,
      scopes: @valid_request["scope"]
    )

    assert {:native_redirect, %{code: code}} =
             Authorization.preauthorize(resource_owner, @valid_request,
               otp_app: :ex_oauth2_provider
             )

    access_grant = QueryHelpers.get_latest_inserted(OauthAccessGrant)

    assert code == access_grant.token
  end

  test "#authorize/3 rejects when no resource owner" do
    assert Authorization.authorize(nil, @valid_request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 error when invalid client", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client, :unprocessable_entity}
  end

  test "#authorize/3 error when no client_id", %{resource_owner: resource_owner} do
    request = Map.delete(@valid_request, "client_id")

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 error when invalid scope", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"scope" => "app:read app:profile"})

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_scope, :unprocessable_entity}
  end

  describe "#authorize/3 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{resource_owner: resource_owner, application: application}
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "public profile"})

      assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_scope, :unprocessable_entity}
    end

    test "generates grant", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "public"})

      assert {:native_redirect, %{code: code}} =
               Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider)

      access_grant = Repo.get_by(OauthAccessGrant, token: code)
      assert access_grant.resource_owner_id == resource_owner.id
    end
  end

  test "#authorize/3 error when invalid redirect uri", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"redirect_uri" => "/invalid/path"})

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_redirect_uri, :unprocessable_entity}
  end

  test "#authorize/3 generates grant", %{resource_owner: resource_owner} do
    assert {:native_redirect, %{code: code}} =
             Authorization.authorize(resource_owner, @valid_request, otp_app: :ex_oauth2_provider)

    access_grant = Repo.get_by(OauthAccessGrant, token: code)

    assert access_grant.resource_owner_id == resource_owner.id

    assert access_grant.expires_in ==
             Config.authorization_code_expires_in(otp_app: :ex_oauth2_provider)

    assert access_grant.scopes == @valid_request["scope"]
  end

  test "#authorize/3 generates grant with redirect uri", %{
    resource_owner: resource_owner,
    application: application
  } do
    QueryHelpers.change!(application,
      redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
    )

    request =
      Map.merge(@valid_request, %{
        "redirect_uri" => "https://example.com/path?param=1",
        "state" => 40_612
      })

    assert {:redirect, redirect_uri} =
             Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider)

    access_grant = QueryHelpers.get_latest_inserted(OauthAccessGrant)

    assert redirect_uri ==
             "https://example.com/path?code=#{access_grant.token}&param=1&state=40612"
  end

  test "#deny/3 error when no resource owner" do
    assert Authorization.deny(nil, @valid_request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#deny/3 error when invalid client", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Authorization.deny(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client, :unprocessable_entity}
  end

  test "#deny/3 error when no client_id", %{resource_owner: resource_owner} do
    request = Map.delete(@valid_request, "client_id")

    assert Authorization.deny(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#deny/3", %{resource_owner: resource_owner} do
    assert Authorization.deny(resource_owner, @valid_request, otp_app: :ex_oauth2_provider) ==
             {:error, @access_denied, :unauthorized}
  end

  test "#deny/3 with redirection uri", %{application: application, resource_owner: resource_owner} do
    QueryHelpers.change!(application,
      redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
    )

    request =
      Map.merge(@valid_request, %{
        "redirect_uri" => "https://example.com/path?param=1",
        "state" => 40_612
      })

    assert Authorization.deny(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:redirect,
              "https://example.com/path?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.&param=1&state=40612"}
  end

  test "#authorize/3 rejects non-string parameters without raising", %{
    resource_owner: resource_owner
  } do
    for {field, value} <- [
          {"client_id", ["x"]},
          {"redirect_uri", ["https://example.com/cb"]},
          {"scope", ["read"]},
          {"state", ["abc"]},
          {"response_type", ["code"]}
        ] do
      request = Map.put(@valid_request, field, value)

      assert {:error, %{error: _}, _status} =
               Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider)
    end
  end

  test "Error.add_error/2 maps changeset errors to invalid_request instead of raising" do
    changeset =
      %OauthAccessGrant{}
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.add_error(:scopes, "is invalid")

    assert {:error, %{error: %{error: :invalid_request}, error_http_status: :bad_request}} =
             ExOauth2Provider.Utils.Error.add_error({:ok, %{}}, changeset)
  end
end
