defmodule ExOauth2Provider.Token.AuthorizationCode do
  @moduledoc """
  Functions for dealing with authorization code strategy.
  """
  alias ExOauth2Provider.{
    AccessGrants,
    AccessTokens,
    Config,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error
  }

  @doc """
  Will grant access token by client credentials.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "code" => "1jf6a",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "redirect_uri" => "https://example.com/",
        "grant_type" => "authorization_code"
      }, otp_app: :my_app)

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "authorization_code"} = request, config \\ []) do
    {:ok, %{request: request}}
    |> Utils.load_client(config)
    |> load_active_access_grant(config)
    |> validate_redirect_uri()
    |> validate_pkce()
    |> issue_access_token_by_grant(config)
    |> Response.response(config)
  end

  defp issue_access_token_by_grant({:error, params}, _config), do: {:error, params}

  defp issue_access_token_by_grant(
         {:ok, %{access_grant: access_grant, request: _} = params},
         config
       ) do
    repo = Config.repo(config)
    token_params = %{use_refresh_token: Config.use_refresh_token?(config)}

    result =
      repo.transaction(fn ->
        with {:ok, revoked_grant} <- revoke_grant(access_grant, config),
             {:ok, resource_owner} <-
               Utils.lock_resource_owner(access_grant.resource_owner, config) do
          maybe_create_access_token(resource_owner, revoked_grant, token_params, config)
        end
      end)

    case result do
      {:ok, {:ok, access_token}} -> {:ok, Map.put(params, :access_token, access_token)}
      {:ok, {:error, error}} -> Error.add_error({:ok, params}, error)
      {:error, error} -> Error.add_error({:ok, params}, error)
    end
  end

  defp revoke_grant(access_grant, config) do
    case AccessGrants.revoke_once(access_grant, config) do
      {:ok, revoked_grant} -> {:ok, revoked_grant}
      {:error, :already_revoked} -> {:error, Error.invalid_grant()}
    end
  end

  defp maybe_create_access_token(
         resource_owner,
         %{application: application, scopes: scopes},
         token_params,
         config
       ) do
    token_params = Map.merge(token_params, %{scopes: scopes, application: application})

    resource_owner
    |> AccessTokens.get_token_for(application, scopes, config)
    |> case do
      nil -> AccessTokens.create_token(resource_owner, token_params, config)
      access_token -> {:ok, access_token}
    end
  end

  defp load_active_access_grant(
         {:ok, %{client: client, request: %{"code" => code}} = params},
         config
       )
       when is_binary(code) do
    client
    |> AccessGrants.get_active_grant_for(code, config)
    |> Config.repo(config).preload([:resource_owner, :application])
    |> case do
      nil -> Error.add_error({:ok, params}, Error.invalid_grant())
      %{resource_owner: nil} -> Error.add_error({:ok, params}, Error.invalid_grant())
      access_grant -> {:ok, Map.put(params, :access_grant, access_grant)}
    end
  end

  defp load_active_access_grant({:ok, %{request: %{"code" => _}} = params}, _config),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  defp load_active_access_grant({:ok, params}, _config),
    do: Error.add_error({:ok, params}, Error.invalid_grant())

  defp load_active_access_grant({:error, error}, _config), do: {:error, error}

  defp validate_redirect_uri({:error, params}), do: {:error, params}

  defp validate_redirect_uri(
         {:ok, %{request: %{"redirect_uri" => redirect_uri}, access_grant: grant} = params}
       )
       when is_binary(redirect_uri) do
    case grant.redirect_uri == redirect_uri do
      true -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_grant())
    end
  end

  defp validate_redirect_uri({:ok, %{request: %{"redirect_uri" => _}} = params}),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  defp validate_redirect_uri({:ok, params}),
    do: Error.add_error({:ok, params}, Error.invalid_grant())

  @code_verifier_regex ~r/\A[A-Za-z0-9\-._~]{43,128}\z/

  defp validate_pkce({:error, params}), do: {:error, params}

  defp validate_pkce(
         {:ok,
          %{access_grant: %{code_challenge: nil, application: %{client_type: "public"}}} = params}
       ) do
    Error.add_error({:ok, params}, Error.invalid_grant())
  end

  defp validate_pkce({:ok, %{access_grant: %{code_challenge: nil}, request: request} = params}) do
    case Map.get(request, "code_verifier") do
      nil -> {:ok, params}
      _ -> Error.add_error({:ok, params}, Error.invalid_grant())
    end
  end

  defp validate_pkce(
         {:ok,
          %{
            request: %{"code_verifier" => code_verifier},
            access_grant: %{code_challenge: code_challenge, code_challenge_method: "S256"}
          } = params}
       )
       when is_binary(code_verifier) and is_binary(code_challenge) and
              byte_size(code_challenge) > 0 do
    if Regex.match?(@code_verifier_regex, code_verifier) do
      hashed_verifier = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)

      if Plug.Crypto.secure_compare(hashed_verifier, code_challenge) do
        {:ok, params}
      else
        Error.add_error({:ok, params}, Error.invalid_grant())
      end
    else
      Error.add_error({:ok, params}, Error.invalid_grant())
    end
  end

  defp validate_pkce({:ok, %{access_grant: %{code_challenge: _}} = params}) do
    Error.add_error({:ok, params}, Error.invalid_grant())
  end
end
