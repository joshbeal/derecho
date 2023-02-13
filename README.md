<h1 align="center">Derecho: Privacy Pools with Proof-Carrying Disclosures</h1>

This repository contains an implementation of *proof-carrying disclosures* as specified in the Derecho paper.

This library is released under the MIT License and the Apache v2 License (see [License](#license)).

The implementation is based on [Arkworks](https://github.com/arkworks-rs/) and uses the building blocks of [IVLS](https://github.com/arkworks-rs/ivls). The disclosure creation and verification functionality uses the [Arkworks PCD](https://github.com/arkworks-rs/pcd/) library, which supports the construction of [\[BCLMS21\]](https://eprint.iacr.org/2020/1618).

**NOTE:** This is an academic proof-of-concept implementation. This library is not intended for production usage.

## Setup

This project uses the [nix](https://nixos.org) package manager. Installation instructions can be found [here](https://nixos.org/download.html).

To activate a shell with the target environment:

```
 nix-shell --pure
```

## Build

To build the project:

```
cargo build --release
```

## Test

To execute the tests with single-threaded execution:

```
cargo test --all  -- --nocapture
```

To execute the tests with multi-threaded execution:
```
RAYON_NUM_THREADS=12 cargo test --all  -- --nocapture
```

For best performance, modify `RAYON_NUM_THREADS` based on your CPU configuration.

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
