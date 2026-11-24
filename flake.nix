{
  description = "ex_oauth2_provider";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ parts, ... }:
    parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, ... }:
        let
          beamPackages = pkgs.beam_minimal.packages.erlang_29;
          erlang = beamPackages.erlang;
          elixir = beamPackages.elixir_1_20;
        in
        {
          devShells.default = pkgs.mkShell {
            packages = [
              erlang
              elixir
              pkgs.git
            ];

            env = {
              MIX_OS_DEPS_COMPILE_PARTITION_COUNT = "16";
              ERL_AFLAGS = "+pc unicode -kernel shell_history enabled";
              ELIXIR_ERL_OPTIONS = "+fnu +sssdio 128";
            };
          };
        };
    };
}
