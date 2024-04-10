let
# Mozilla Overlay
moz_overlay = import (
  builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"
);

nixpkgs = import (builtins.fetchTarball https://github.com/NixOS/nixpkgs/archive/22.11.tar.gz) {
  overlays = [ moz_overlay ];
  config = {};
};

frameworks = nixpkgs.darwin.apple_sdk.frameworks;
rust =
  nixpkgs.rust-bin.nightly."2023-02-12".default.override {
    extensions = [
      "rust-src"
    ];
  };

in
with nixpkgs;

pkgs.mkShell {
  name = "derecho-env";
  buildInputs = [ rust ];

  nativeBuildInputs = [
    clang
    llvm
    zsh
    vim
  ] ++ (
    lib.optionals stdenv.isDarwin [
      frameworks.Security
      frameworks.CoreServices
      frameworks.CoreFoundation
      frameworks.Foundation
    ]
  );

  # ENV Variables
  LIBCLANG_PATH = "${llvmPackages.libclang}/lib";

  # Post Shell Hook
  shellHook = ''
    echo "Using ${rust.name}"

  '' + (
    if !pkgs.stdenv.isDarwin then
      ""
    else ''
      # Cargo wasn't able to find CF during a `cargo test` run on Darwin.
      export NIX_LDFLAGS="-F${frameworks.CoreFoundation}/Library/Frameworks -framework CoreFoundation $NIX_LDFLAGS";
    ''
  );
}  