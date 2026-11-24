defmodule ExOauth2Provider.Token.Utils do
  @moduledoc false

  import Ecto.Query
  alias ExOauth2Provider.{Applications, Config, Utils.Error}

  @doc false
  @spec load_client({:ok, map()}, keyword()) :: {:ok, map()} | {:error, map()}
  def load_client({:ok, %{request: %{"client_id" => client_id} = request} = params}, config)
      when is_binary(client_id) do
    case Map.get(request, "client_secret", "") do
      client_secret when is_binary(client_secret) ->
        case Applications.load_application(client_id, client_secret, config) do
          nil -> Error.add_error({:ok, params}, Error.invalid_client())
          client -> {:ok, Map.merge(params, %{client: client})}
        end

      _ ->
        Error.add_error({:ok, params}, Error.invalid_request())
    end
  end

  def load_client({:ok, params}, _config),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  def load_client({:error, params}, _config), do: {:error, params}

  @doc false
  @spec lock_resource_owner(Ecto.Schema.t() | nil, keyword()) ::
          {:ok, Ecto.Schema.t()} | {:error, {:error, map(), atom()}}
  def lock_resource_owner(%owner_schema{id: owner_id} = owner, config)
      when not is_nil(owner_id) do
    repo = Config.repo(config)
    source = Ecto.get_meta(owner, :source)
    prefix = Ecto.get_meta(owner, :prefix)
    opts = if prefix, do: [prefix: prefix], else: []

    from(u in {source, owner_schema}, where: u.id == ^owner_id, lock: "FOR SHARE")
    |> repo.one(opts)
    |> case do
      nil -> {:error, Error.invalid_grant()}
      locked_owner -> {:ok, locked_owner}
    end
  end

  def lock_resource_owner(_owner, _config), do: {:error, Error.invalid_grant()}
end
