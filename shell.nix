with builtins;

let
  sources = import ./nix/sources.nix {};
  haskellNix = import sources.haskellNix {};
  pkgs = import haskellNix.sources.nixpkgs-unstable haskellNix.nixpkgsArgs;

  project = pkgs.haskell-nix.cabalProject {
    src = ./.;
    compiler-nix-name = "ghc8107";
    index-state = "2021-11-09T00:00:00Z";
    name = "oauthenticated";
  };

in project.shellFor {
    exactDeps = true;
    tools = {
      cabal = "3.4.0.0";
    };
    packages = ps: [ps.oauthenticated];
  }
