# epoxy
Epoxy is an encrypted proxy for browser javascript.
It allows you to make requests that bypass CORS without compromising security by running SSL/TLS inside webassembly and using the [Wisp protocol](https://github.com/mercuryworkshop/wisp-protocol/) to proxy TCP connections.

It also has a Wisp library implementation for Rust and a performant Wisp server built in Rust.

See the [client readme](client/README.md) and [server readme](server/README.md) for instructions on how to build and use them.

## Fork notes

This fork carries browser-identity TLS shaping on top of upstream epoxy.

- `vendor/rustls` is rustls 0.23.46 with the lyrebird patches applied
  (`sh tools/apply-rustls.sh`). The `[patch.crates-io]` entry in the
  workspace `Cargo.toml` points every rustls consumer at that copy.
- `EpoxyClientOptions::identity` selects the ClientHello voice:
  `Native` (stock rustls), `Brave` (Chromium 158 wire shape) or
  `Firefox` (160 wire shape). The profile data lives in the patched
  rustls (`rustls::client::browser_profiles`); the small `epoxy-hello`
  crate maps identities onto it and `epoxy-client` applies it at the
  TLS seam.
- Honest caveat: the published wasm client stays on the ring provider,
  so the pinned cipher/signature lists degrade to the ring-offerable
  subset and the X25519MLKEM768 group is unavailable. The native
  `wire-parity` runner uses the aws-lc provider and reaches full parity;
  the `live-parity` workflow re-proves it against a live fingerprint
  endpoint.
- License is unchanged (upstream AGPL-3.0).
