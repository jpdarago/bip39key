{
  description = "Nix flake for bip39key";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

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
        version = "1.4.3";

        src = pkgs.fetchFromGitHub {
          owner = "jpdarago";
          repo  = "bip39key";
          rev   = "v${version}";
          hash  = "sha256-U28settSyuTvrgx+pWeOBjer0Zi9CVjL/KjW7FhHmJ4=";
        };

        cargoHash = "sha256-w7U4I/Yzy/OGoWZQ9dpKi3zl2R3sOZP9vv71gFsEpcQ=";

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
