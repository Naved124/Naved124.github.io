{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "ruby-dev-shell";

  # These are the build tools (compilers, make, pkg-config)
  nativeBuildInputs = with pkgs; [
    pkg-config
    gnumake
    gcc
    libiconv
  ];

  # These are the runtime libraries required by your gems
  buildInputs = with pkgs; [
    ruby
    bundler
    libffi      # Fixes "checking for ffi.h... no"
    zlib
    openssl
    readline
  ];

  # This ensures the gems can find the libraries during the build process
  shellHook = ''
    export GEM_HOME=$PWD/vendor/bundle
    export PATH=$GEM_HOME/bin:$PATH
  '';
}