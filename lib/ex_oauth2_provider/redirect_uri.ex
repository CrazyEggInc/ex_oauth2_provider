defmodule ExOauth2Provider.RedirectURI do
  @moduledoc """
  Functions for dealing with redirect uri.
  """
  alias ExOauth2Provider.{Config, Utils}

  @doc """
  Validates if a url can be used as a redirect_uri.

  Validates according to [RFC 6749 3.1.2](https://tools.ietf.org/html/rfc6749#section-3.1.2)
  and [RFC 8252 7.1](https://tools.ietf.org/html/rfc8252#section-7.1). The validation is
  skipped if the redirect uri is the same as the `:native_redirect_uri` configuration
  setting.
  """
  @disallowed_schemes ~w(javascript data vbscript file blob)
  @control_or_whitespace_regex ~r/[\x00-\x1F\x7F\s]/u

  @spec validate(binary() | nil, keyword()) :: {:ok, binary()} | {:error, binary()}
  def validate(nil, config), do: validate("", config)

  def validate(url, config) when is_binary(url) do
    cond do
      String.trim(url) == "" ->
        {:error, "Redirect URI cannot be blank"}

      Regex.match?(@control_or_whitespace_regex, url) ->
        {:error, "Redirect URI cannot contain whitespace or control characters"}

      native_redirect_uri?(url, config) ->
        {:ok, url}

      true ->
        case URI.new(url) do
          {:ok, uri} -> do_validate(url, uri, config)
          {:error, _} -> {:error, "Redirect URI must be an absolute URI"}
        end
    end
  end

  def validate(_url, _config), do: {:error, "Redirect URI must be a string"}

  defp do_validate(_url, %{fragment: fragment}, _config) when not is_nil(fragment),
    do: {:error, "Redirect URI cannot contain fragments"}

  defp do_validate(_url, %{userinfo: userinfo}, _config) when not is_nil(userinfo),
    do: {:error, "Redirect URI cannot contain userinfo"}

  defp do_validate(url, %{scheme: scheme} = uri, config) when is_binary(scheme) do
    scheme_down = String.downcase(scheme)

    cond do
      scheme_down in @disallowed_schemes ->
        {:error, "Redirect URI scheme is not allowed"}

      scheme_down in ["http", "https"] and (is_nil(uri.host) or uri.host == "") ->
        {:error, "Redirect URI must include a host"}

      invalid_ssl_uri?(uri, scheme_down, config) ->
        {:error, "Redirect URI must be an HTTPS/SSL URI"}

      true ->
        {:ok, url}
    end
  end

  defp do_validate(_url, _uri, _config),
    do: {:error, "Redirect URI must be an absolute URI"}

  defp invalid_ssl_uri?(uri, "http", config) do
    Config.force_ssl_in_redirect_uri?(config) and
      not (Keyword.get(config, :allow_public_loopback_redirect_uri, false) and loopback_uri?(uri))
  end

  defp invalid_ssl_uri?(_uri, _scheme, _config), do: false

  @doc false
  @deprecated "Use `matches?/3` instead"
  def matches?(uri, client_uri), do: matches?(uri, client_uri, [])

  @doc """
  Check if uri matches client uri
  """
  @spec matches?(binary(), binary(), keyword()) :: boolean()
  def matches?(uri, client_uri, config) when is_binary(uri) and is_binary(client_uri) do
    with {:ok, parsed_uri} <- URI.new(uri),
         {:ok, parsed_client_uri} <- URI.new(client_uri) do
      matches?(parsed_uri, parsed_client_uri, config)
    else
      _ -> false
    end
  end

  @spec matches?(URI.t(), URI.t(), keyword()) :: boolean()
  def matches?(%URI{} = uri, %URI{} = client_uri, config) do
    if allow_public_loopback_redirect_uri?(uri, client_uri, config) do
      true
    else
      case Config.redirect_uri_match_fun(config) do
        nil -> client_uri == %{uri | query: nil}
        fun -> fun.(uri, client_uri, config)
      end
    end
  end

  @doc """
  Check if a url matches a client redirect_uri
  """
  @spec valid_for_authorization?(binary(), binary(), keyword()) :: boolean()
  def valid_for_authorization?(url, client_url, config)
      when is_binary(url) and is_binary(client_url) do
    url
    |> validate(config)
    |> do_valid_for_authorization?(client_url, config)
  end

  def valid_for_authorization?(_url, _client_url, _config), do: false

  defp do_valid_for_authorization?({:error, _error}, _client_url, _config), do: false

  defp do_valid_for_authorization?({:ok, url}, client_url, config) do
    client_url
    |> String.split()
    |> Enum.any?(&matches?(url, &1, config))
  end

  @doc """
  Check if a url is native
  """
  @spec native_redirect_uri?(binary(), keyword()) :: boolean()
  def native_redirect_uri?(url, config) do
    Config.native_redirect_uri(config) == url
  end

  @doc """
  Adds query parameters to uri
  """
  @spec uri_with_query(binary() | URI.t(), map()) :: binary()
  def uri_with_query(uri, query) when is_binary(uri) do
    uri
    |> URI.parse()
    |> uri_with_query(query)
  end

  def uri_with_query(%URI{} = uri, query) do
    query = add_query_params(uri.query || "", query)

    uri
    |> Map.put(:query, query)
    |> to_string()
  end

  defp add_query_params(query, attrs) do
    query
    |> URI.decode_query(attrs)
    |> Utils.remove_empty_values()
    |> URI.encode_query()
  end

  defp allow_public_loopback_redirect_uri?(uri, client_uri, config) do
    Keyword.get(config, :allow_public_loopback_redirect_uri, false) and
      loopback_callback_uri?(uri) and
      uri.scheme == client_uri.scheme and
      loopback_registration_matches?(uri, client_uri)
  end

  defp loopback_registration_matches?(uri, client_uri) do
    (loopback_origin_registration?(client_uri) and same_loopback_host?(uri.host, client_uri.host)) or
      (loopback_path_registration?(client_uri) and
         uri.host == client_uri.host and
         uri.path == client_uri.path and
         uri.query == client_uri.query)
  end

  defp loopback_origin_registration?(%URI{
         scheme: "http",
         host: host,
         path: path,
         port: port,
         userinfo: nil,
         query: nil,
         fragment: nil
       })
       when host in ["127.0.0.1", "localhost", "::1"] and port in [nil, 80] and
              path in [nil, "", "/"],
       do: true

  defp loopback_origin_registration?(_uri), do: false

  defp loopback_path_registration?(%URI{
         scheme: "http",
         host: host,
         path: path,
         userinfo: nil,
         fragment: nil
       })
       when host in ["127.0.0.1", "localhost", "::1"] and
              is_binary(path) and path not in ["", "/"],
       do: true

  defp loopback_path_registration?(_uri), do: false

  defp loopback_callback_uri?(%URI{
         scheme: "http",
         host: host,
         port: port,
         userinfo: nil,
         fragment: nil
       })
       when host in ["127.0.0.1", "localhost", "::1"] and is_integer(port),
       do: true

  defp loopback_callback_uri?(_uri), do: false

  defp loopback_uri?(%URI{scheme: scheme, host: host, userinfo: nil})
       when is_binary(scheme) and host in ["127.0.0.1", "localhost", "::1"] do
    String.downcase(scheme) == "http"
  end

  defp loopback_uri?(_uri), do: false

  defp same_loopback_host?(host_a, host_b) do
    loopback_host?(host_a) and loopback_host?(host_b)
  end

  defp loopback_host?(host) when host in ["127.0.0.1", "localhost", "::1"], do: true
  defp loopback_host?(_host), do: false
end
