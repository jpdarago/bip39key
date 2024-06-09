{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  packages = with pkgs; [ rustc cargo python311 pipenv ];
}
