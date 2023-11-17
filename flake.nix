{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }: 
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      pyprj = pkgs.lib.trivial.importTOML ./pyproject.toml;
      packageOverrides = self: super: {
        mbntools = self.buildPythonPackage {
          pname = pyprj.project.name;
          version = pyprj.project.version;
          pyproject = true;

          src = ./.;

          nativeBuildInputs = map (n: builtins.getAttr n self) pyprj.build-system.requires;
          propagatedBuildInputs = map (n: builtins.getAttr n self) (pyprj.project.dependencies ++ pyprj.project.optional-dependencies.color);
        };
      };
      python' = pkgs.python311.override { inherit packageOverrides; };
    in {
      packages.default = python'.pkgs.mbntools;
      devShells.default = pkgs.mkShell {
        packages = [
          (python'.withPackages (p: with p; [ mbntools pytest ]))
          pkgs.nodePackages.pyright
          ];
      };
      apps.default = self.apps.${system}.mbn-extract;
      apps.mbn-extract = {
        type = "app";
        program = "${self.packages.${system}.default}/bin/extract";
      };
    });
}
