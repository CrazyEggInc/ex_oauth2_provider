defmodule ExOauth2Provider.Token.RefreshToken do
  @moduledoc """
  Functions for dealing with refresh token strategy.
  """

  import Ecto.Query

  alias ExOauth2Provider.{
    AccessTokens,
    Config,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error
  }

  @doc """
  Will grant access token by refresh token.

  ## Example
      ExOauth2Provider.Token.authorize(%{
        "grant_type" => "refresh_token",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "refresh_token" => "1jf6a"
      }, otp_app: :my_app)

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "refresh_token"} = request, config \\ []) do
    {:ok, %{request: request}}
    |> Utils.load_client(config)
    |> load_access_token_by_refresh_token(config)
    |> issue_access_token_by_refresh_token(config)
    |> Response.response(config)
  end

  defp load_access_token_by_refresh_token(
         {:ok, %{client: client, request: %{"refresh_token" => refresh_token}} = params},
         config
       )
       when is_binary(refresh_token) do
    access_token =
      client
      |> AccessTokens.get_by_refresh_token_for(refresh_token, config)
      |> Config.repo(config).preload([:resource_owner, :application])

    cond do
      is_nil(access_token) ->
        Error.add_error({:ok, params}, Error.invalid_request())

      AccessTokens.is_revoked?(access_token) ->
        Error.add_error({:ok, params}, Error.invalid_request())

      is_nil(access_token.resource_owner) ->
        Error.add_error({:ok, params}, Error.invalid_grant())

      true ->
        {:ok, Map.put(params, :refresh_token, access_token)}
    end
  end

  defp load_access_token_by_refresh_token(params, _config),
    do: Error.add_error(params, Error.invalid_request())

  defp issue_access_token_by_refresh_token({:error, params}, _config), do: {:error, params}

  defp issue_access_token_by_refresh_token(
         {:ok, %{refresh_token: refresh_token, request: _} = params},
         config
       ) do
    repo = Config.repo(config)

    result =
      repo.transaction(fn ->
        token_params = token_params(refresh_token, config)

        with {:ok, current_token} <- consume_or_lock_refresh_token(refresh_token, config),
             {:ok, resource_owner} <- lock_resource_owner(current_token, config) do
          AccessTokens.create_token(resource_owner, token_params, config)
        end
      end)

    case result do
      {:ok, {:ok, access_token}} -> {:ok, Map.merge(params, %{access_token: access_token})}
      {:ok, {:error, error}} -> Error.add_error({:ok, params}, error)
      {:error, error} -> Error.add_error({:ok, params}, error)
    end
  end

  defp token_params(%{scopes: scopes, application: application} = refresh_token, config) do
    params = %{scopes: scopes, application: application, use_refresh_token: true}

    case Config.refresh_token_revoked_on_use?(config) do
      true -> Map.put(params, :previous_refresh_token, refresh_token)
      false -> params
    end
  end

  defp consume_or_lock_refresh_token(refresh_token, config) do
    if Config.refresh_token_revoked_on_use?(config) do
      case AccessTokens.revoke_once(refresh_token, config) do
        {:ok, revoked_token} -> {:ok, revoked_token}
        {:error, :already_revoked} -> {:error, Error.invalid_request()}
      end
    else
      lock_unrevoked_refresh_token(refresh_token, config)
    end
  end

  defp lock_unrevoked_refresh_token(%struct{id: id}, config) do
    from(t in struct, where: t.id == ^id and is_nil(t.revoked_at), lock: "FOR SHARE")
    |> Config.repo(config).one()
    |> case do
      nil -> {:error, Error.invalid_request()}
      token -> {:ok, token}
    end
  end

  defp lock_resource_owner(%{resource_owner_id: owner_id}, config) when not is_nil(owner_id) do
    repo = Config.repo(config)
    owner_schema = Config.resource_owner(config)

    from(u in owner_schema, where: u.id == ^owner_id, lock: "FOR SHARE")
    |> repo.one()
    |> case do
      nil -> {:error, Error.invalid_grant()}
      owner -> {:ok, owner}
    end
  end

  defp lock_resource_owner(_token, _config), do: {:error, Error.invalid_grant()}
end
