{
  description = "xdb";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      imports = [ inputs.treefmt-nix.flakeModule ];

      perSystem =
        { config, pkgs, ... }:
        {
          treefmt = {
            projectRootFile = "flake.nix";
            programs.clang-format.enable = true;
            programs.nixfmt.enable = true;
            settings.formatter.gersemi = {
              command = "${pkgs.gersemi}/bin/gersemi";
              options = [ "-i" ];
              includes = [
                "{,**/}CMakeLists.txt"
                "{,**/}*.cmake"
              ];
            };
          };

          devShells.default =
            pkgs.mkShell.override
              {
                stdenv = pkgs.llvmPackages.stdenv;
              }
              {
                nativeBuildInputs = with pkgs; [
                  cmake
                  ninja
                  pkg-config
                  vcpkg
                  clang-tools

                  # Required by libedit
                  autoconf
                  autoconf-archive
                  automake
                  libtool

                  config.treefmt.build.wrapper
                ];

                buildInputs = with pkgs; [
                  ncurses # Required by libedit
                ];

                hardeningDisable = [ "all" ];

                env.VCPKG_ROOT = "${pkgs.vcpkg}/share/vcpkg";
              };
        };
    };
}
