{
  description = "Nix flake for bip39key";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
  let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
      f {
        pkgs = import nixpkgs { inherit system; };
        inherit system;
      }
    );

    muslTarget = system: {
      "x86_64-linux"  = "x86_64-unknown-linux-musl";
      "aarch64-linux" = "aarch64-unknown-linux-musl";
    }.${system};

  in {
    packages = forAllSystems ({ pkgs, system }: {
      # Static musl build (reproducible, portable)
      bip39key = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
        pname = "bip39key";
        version = "1.5.0";

        src = ./.;

        cargoLock.lockFile = ./Cargo.lock;

        # Integration tests need gpg and ssh-keygen
        doCheck = true;
        nativeCheckInputs = with pkgs; [
          gnupg
          openssh
        ];

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
