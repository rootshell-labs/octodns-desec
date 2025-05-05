{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    pre-commit = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    pre-commit,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      checks = {
        pre-commit-check = pre-commit.lib.${system}.run {
          src = ./.;
          hooks = {
            editorconfig-checker.enable = true;
            alejandra.enable = true;
            deadnix.enable = true;
            flake-checker.enable = true;
            statix.enable = true;
            check-python.enable = true;
            sort-requirements-txt.enable = true;
            check-builtin-literals.enable = true;
            autoflake.enable = true;
          };
        };
      };
      packages = rec {
        octodns-desec = with pkgs.python3Packages;
          buildPythonPackage rec {
            pname = "octodns-desec";
            version = "1.0.0";
            pyproject = true;

            disabled = pythonOlder "3.10";

            src = ./.;

            nativeBuildInputs = [
              setuptools
            ];

            propagatedBuildInputs = [
              pkgs.octodns
              requests
            ];

            pythonImportsCheck = ["octodns_desec"];

            nativeCheckInputs = [
              pytestCheckHook
              requests-mock
            ];

            meta = with pkgs.lib; {
              description = "deSEC DNS provider for octoDNS";
              homepage = "https://github.com/rootshell-labs/octodns-desec";
              changelog = "https://github.com/rootshell-labs/octodns-desec/blob/${src.rev}/CHANGELOG.md";
              license = licenses.mit;
              maintainers = [
                {
                  github = "blackdotraven";
                  githubId = 5709618;
                  name = "blackdotraven";
                }
                pkgs.lib.maintainers.tilcreator
              ];
            };
          };
        default = octodns-desec;
      };
    });
}
