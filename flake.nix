{
  description = "ex_oauth2_provider";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        erlang = pkgs.beam.interpreters.erlang_27;
        beamPkgs = pkgs.beam.packagesWith erlang;
        elixir = beamPkgs.elixir_1_17;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            elixir
            pkgs.git
          ];

          env = {
            ERL_INCLUDE_PATH = "${erlang}/lib/erlang/usr/include";
            ERL_AFLAGS = "+pc unicode -kernel shell_history enabled";
            ELIXIR_ERL_OPTIONS = "+sssdio 128";
          };
        };
      }
    );
}
