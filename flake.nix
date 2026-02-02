{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/89c2b2330e733d6cdb5eae7b899326930c2c0648";
    flake-parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
    system.url = "github:nix-systems/default";
    services-flake.url = "github:juspay/services-flake";
    process-compose-flake.url = "github:Platonic-Systems/process-compose-flake";
  };
  outputs = inputs@{ self, nixpkgs, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.system;
      imports = [
        inputs.haskell-flake.flakeModule
        inputs.process-compose-flake.flakeModule
      ];
      perSystem = { self', pkgs, config, ... }: {

        formatter = pkgs.nixpkgs-fmt;
        process-compose.redis-service = { config, ... }: {
          imports = [
            inputs.services-flake.processComposeModules.default
          ];
          services.redis-cluster."cluster1".enable = true;
          services.redis."redis".enable = true;
        };
        haskellProjects.default = {
          basePackages = pkgs.haskell.packages.ghc98;
          autoWire = [ "packages" ];
          devShell.tools = hp: {
            haskell-language-server = null;
          };
          
          # Optional: Disable the HLS check if you don't want it running in 'nix flake check'
          devShell.hlsCheck.enable = false;
        };
        packages = {
          regex-tdfa.source="1.3.2.5";
          };
        packages.default = self'.packages.hedis;
        devShells.default = pkgs.mkShell {
          name = "hedis";
          inputsFrom = [
            config.haskellProjects.default.outputs.devShell
          ];
        };
      };
    };
}

