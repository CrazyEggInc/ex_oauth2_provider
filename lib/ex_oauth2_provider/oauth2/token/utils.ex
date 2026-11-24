defmodule ExOauth2Provider.Token.Utils do
  @moduledoc false

  alias ExOauth2Provider.{Applications, Utils.Error}

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
end
