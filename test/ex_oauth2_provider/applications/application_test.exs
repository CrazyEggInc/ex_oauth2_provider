defmodule ExOauth2Provider.Applications.ApplicationTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Applications.Application
  alias Dummy.OauthApplications.OauthApplication

  describe "changeset/2 with existing application" do
    setup do
      application = Ecto.put_meta(%OauthApplication{}, state: :loaded)

      {:ok, application: application}
    end

    test "validates", %{application: application} do
      changeset = Application.changeset(application, %{name: ""})
      assert changeset.errors[:name]
    end

    test "validates uid", %{application: application} do
      changeset = Application.changeset(application, %{uid: ""})
      assert changeset.errors[:uid]
    end

    test "validates secret", %{application: application} do
      changeset = Application.changeset(application, %{secret: nil})
      assert changeset.errors[:secret] == {"can't be blank", []}

      changeset = Application.changeset(application, %{secret: ""})
      assert changeset.errors[:secret] == {"can't be blank", []}

      public_changeset = Application.changeset(application, %{client_type: "public", secret: ""})
      assert is_nil(public_changeset.errors[:secret])
      assert Ecto.Changeset.get_field(public_changeset, :secret) == ""

      # Switching public client back to confidential without a non-empty secret fails
      public_app = %{application | client_type: "public", secret: ""}
      switch_changeset = Application.changeset(public_app, %{client_type: "confidential"})
      assert switch_changeset.errors[:secret] == {"can't be blank", []}
    end

    test "requires valid redirect uri", %{application: application} do
      changeset = Application.changeset(application, %{redirect_uri: ""})
      assert changeset.errors[:redirect_uri]
    end

    test "require valid redirect uri", %{application: application} do
      ["", "invalid", "https://example.com invalid", "https://example.com http://example.com"]
      |> Enum.each(fn redirect_uri ->
        changeset = Application.changeset(application, %{redirect_uri: redirect_uri})
        assert changeset.errors[:redirect_uri]
      end)
    end

    test "allows loopback http redirect uri for public clients", %{application: application} do
      changeset =
        Application.changeset(application, %{
          client_type: "public",
          redirect_uri: "http://127.0.0.1"
        })

      refute changeset.errors[:redirect_uri]
    end

    test "doesn't require scopes", %{application: application} do
      changeset = Application.changeset(application, %{scopes: ""})
      refute changeset.errors[:scopes]
    end
  end

  defmodule OverrideOwner do
    @moduledoc false

    use Ecto.Schema
    use ExOauth2Provider.Applications.Application, otp_app: :ex_oauth2_provider

    if System.get_env("UUID") do
      @primary_key {:id, :binary_id, autogenerate: true}
      @foreign_key_type :binary_id
    end

    schema "oauth_applications" do
      belongs_to(:owner, __MODULE__)

      application_fields()
      timestamps()
    end
  end

  test "with overridden `:owner`" do
    assert %Ecto.Association.BelongsTo{owner: OverrideOwner} =
             OverrideOwner.__schema__(:association, :owner)
  end
end
