import Config

# use config only for tests
if config_env() == :test do
  # Print only warnings and errors during test
  config :logger, level: :warning

  config :ex_oauth2_provider, namespace: Dummy

  config :ex_oauth2_provider, ExOauth2Provider,
    repo: Dummy.Repo,
    resource_owner: Dummy.Users.User,
    default_scopes: ~w(public),
    optional_scopes: ~w(read write),
    password_auth: {Dummy.Auth, :auth},
    use_refresh_token: true,
    revoke_refresh_token_on_use: true,
    grant_flows: ~w(authorization_code client_credentials)

  config :ex_oauth2_provider, Dummy.Repo,
    database: System.get_env("POSTGRES_DATABASE") || "ex_oauth2_provider_test",
    username: System.get_env("POSTGRES_USERNAME") || "postgres",
    password: System.get_env("POSTGRES_PASSWORD") || "postgres",
    hostname: System.get_env("POSTGRES_HOSTNAME") || "localhost",
    port: (System.get_env("POSTGRES_PORT") || "5432") |> String.to_integer(),
    pool: Ecto.Adapters.SQL.Sandbox,
    priv: "test/support/priv",
    url: System.get_env("POSTGRES_URL")

end
