{ pkgs, lib, config, inputs, ... }:

{
  packages = with pkgs; [ 
    cargo
    clippy
    git
    gnupg
    openssh
    python314
    rust-analyzer
    rustc
    rustfmt
  ];

  languages = {
    python.enable = true;
    rust.enable = true;
  };

  git-hooks.hooks = {

    black.enable = true;

    rustfmt = {
      enable = true;
      packageOverrides = {
        cargo = pkgs.cargo;
        rustfmt = pkgs.rustfmt;
      };
    };

    clippy = { 
      enable = true;
      packageOverrides = {
        clippy = pkgs.clippy;
      };
    };
  };

  enterTest = ''
    ${pkgs.python3}/bin/python3 test/test.py
  '';
}
