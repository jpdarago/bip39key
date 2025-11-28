{
  description = "Nix flake for bip39key";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

  outputs = { self, nixpkgs }:
  let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
      f {
        pkgs = import nixpkgs { inherit system; };
        inherit system;
      }
    );
  in {
    packages = forAllSystems ({ pkgs, system }: {
      bip39key = pkgs.rustPlatform.buildRustPackage rec {
        pname = "bip39key";
        version = "1.4.4";

        src = ./.;

        cargoLock.lockFile = ./Cargo.lock;

        doCheck = true;

        meta = with pkgs.lib; {
          description = "Generate an OpenPGP/OpenSSH key from a BIP39 mnemonic";
          homepage    = "https://github.com/jpdarago/bip39key";
          license     = licenses.mit;
          mainProgram = "bip39key";
          platforms   = platforms.linux;
        };
      };
    });

    defaultPackage = forAllSystems ({ pkgs, system }: self.packages.${system}.bip39key);
  };
}
