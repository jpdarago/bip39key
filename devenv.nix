{ pkgs, lib, config, inputs, ... }:

{
  packages = with pkgs; [ 
    cargo
    clippy
    git
    gnupg
    openssh
    pgpdump
    rust-analyzer
    rustc
    rustfmt
    cargo-audit
  ];

  env.RUST_ANALYZER_LOCATION = "${pkgs.rust-analyzer}/bin/rust-analyzer";

  env.RUST_BACKTRACE = "1";

  languages = {
    rust.enable = true;
  };

  git-hooks.hooks = {

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
    cargo test --release --test integration
  '';
}
