defmodule ExOauth2Provider.RedirectURITest do
  use ExUnit.Case

  alias ExOauth2Provider.Config
  alias ExOauth2Provider.RedirectURI

  test "validate/2 native url" do
    uri = Config.native_redirect_uri(otp_app: :ex_oauth2_provider)
    assert RedirectURI.validate(uri, []) == {:ok, uri}
  end

  test "validate/2 rejects blank" do
    assert RedirectURI.validate("", []) == {:error, "Redirect URI cannot be blank"}
    assert RedirectURI.validate(nil, []) == {:error, "Redirect URI cannot be blank"}
    assert RedirectURI.validate("  ", []) == {:error, "Redirect URI cannot be blank"}
  end

  test "validate/2 rejects uri with fragment" do
    assert RedirectURI.validate("https://app.co/test#fragment", []) ==
             {:error, "Redirect URI cannot contain fragments"}
  end

  test "validate/2 rejects uri with missing scheme" do
    assert RedirectURI.validate("app.co", []) == {:error, "Redirect URI must be an absolute URI"}
  end

  test "validate/2 rejects relative uri" do
    assert RedirectURI.validate("/abc/123", []) ==
             {:error, "Redirect URI must be an absolute URI"}
  end

  test "validate/2 requires https scheme with `:force_ssl_in_redirect_uri` setting" do
    uri = "http://app.co/"
    assert RedirectURI.validate(uri, []) == {:error, "Redirect URI must be an HTTPS/SSL URI"}
    assert RedirectURI.validate(uri, force_ssl_in_redirect_uri: false) == {:ok, uri}
  end

  test "validate/2 accepts loopback http uri for public clients" do
    uri = "http://127.0.0.1"

    assert RedirectURI.validate(uri, allow_public_loopback_redirect_uri: true) == {:ok, uri}
  end

  test "validate/2 rejects loopback http uri without opt-in" do
    uri = "http://127.0.0.1"

    assert RedirectURI.validate(uri, []) == {:error, "Redirect URI must be an HTTPS/SSL URI"}
  end

  test "validate/2 accepts absolute uri" do
    uri = "https://app.co"
    assert RedirectURI.validate(uri, []) == {:ok, uri}
    uri = "https://app.co/path"
    assert RedirectURI.validate(uri, []) == {:ok, uri}
    uri = "https://app.co/?query=1"
    assert RedirectURI.validate(uri, []) == {:ok, uri}
  end

  test "validate/2 with wild card subdomain" do
    uri = "https://*.app.co/"
    assert RedirectURI.validate(uri, []) == {:ok, uri}
  end

  test "validate/2 with private-use uri" do
    # RFC Spec - OAuth 2.0 for Native Apps
    # https://tools.ietf.org/html/rfc8252#section-7.1

    uri = "com.example.app:/oauth2redirect/example-provider"
    assert RedirectURI.validate(uri, []) == {:ok, uri}
  end

  test "matches?#true" do
    uri = "https://app.co/aaa"
    assert RedirectURI.matches?(uri, uri, [])
  end

  test "matches?#true with custom match method" do
    uri = "https://a.app.co/"
    client_uri = "https://*.app.co/"

    assert RedirectURI.matches?(uri, client_uri,
             redirect_uri_match_fun: fn uri, %{host: "*." <> host} = client_uri, _config ->
               String.ends_with?(uri.host, host) &&
                 %{uri | query: nil} == %{client_uri | host: uri.host, authority: uri.authority}
             end
           )
  end

  test "matches?#true ignores query parameter on comparison" do
    assert RedirectURI.matches?("https://app.co/?query=hello", "https://app.co/", [])
  end

  test "matches?#false" do
    refute RedirectURI.matches?("https://app.co/?query=hello", "https://app.co", [])
  end

  test "matches?#false with domains that doesn't start at beginning" do
    refute RedirectURI.matches?(
             "https://app.co/?query=hello",
             "https://example.com?app.co=test",
             []
           )
  end

  test "valid_for_authorization?#true" do
    uri = "https://app.co/aaa"
    assert RedirectURI.valid_for_authorization?(uri, uri, [])
  end

  test "valid_for_authorization?#false" do
    refute RedirectURI.valid_for_authorization?("https://app.co/aaa", "https://app.co/bbb", [])
  end

  test "valid_for_authorization?#true with array" do
    assert RedirectURI.valid_for_authorization?(
             "https://app.co/aaa",
             "https://example.com/bbb\nhttps://app.co/aaa",
             []
           )
  end

  test "valid_for_authorization?#true for public loopback redirect with dynamic port and path" do
    assert RedirectURI.valid_for_authorization?(
             "http://127.0.0.1:49215/callback/random-path",
             "http://127.0.0.1",
             allow_public_loopback_redirect_uri: true
           )
  end

  test "valid_for_authorization?#true for localhost registration and 127.0.0.1 callback" do
    assert RedirectURI.valid_for_authorization?(
             "http://127.0.0.1:49215/callback/random-path",
             "http://localhost",
             allow_public_loopback_redirect_uri: true
           )
  end

  test "valid_for_authorization?#true for 127.0.0.1 registration and localhost callback" do
    assert RedirectURI.valid_for_authorization?(
             "http://localhost:49215/callback/random-path",
             "http://127.0.0.1",
             allow_public_loopback_redirect_uri: true
           )
  end

  test "valid_for_authorization?#false for public loopback redirect without opt-in" do
    refute RedirectURI.valid_for_authorization?(
             "http://127.0.0.1:49215/callback/random-path",
             "http://127.0.0.1",
             []
           )
  end

  test "valid_for_authorization?#false with invalid uri" do
    uri = "https://app.co/aaa?waffles=abc"
    refute RedirectURI.valid_for_authorization?(uri, uri, [])
  end

  test "uri_with_query/2" do
    assert RedirectURI.uri_with_query("https://example.com/", %{parameter: "value"}) ==
             "https://example.com/?parameter=value"
  end

  test "uri_with_query/2 rejects nil values" do
    assert RedirectURI.uri_with_query("https://example.com/", %{parameter: nil}) ==
             "https://example.com/?"
  end

  test "uri_with_query/2 preserves original query parameters" do
    uri = RedirectURI.uri_with_query("https://example.com/?query1=value", %{parameter: "value"})
    assert Regex.match?(~r/query1=value/, uri)
    assert Regex.match?(~r/parameter=value/, uri)
  end
end
