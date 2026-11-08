// scadaver library target -- exposes the shared ops dispatch and domain types
// for use by integration tests and future library consumers.
//
// The CLI surfaces live here too, behind the `cli` feature, so `src/main.rs` stays a
// thin consumer. Before that, the binary declared the same fourteen files as private
// modules, so every module was compiled twice and every unit test inside them ran in
// both test binaries (46 of the 361 runs were the same test twice).
//
// `model`, `ops`, `protocol` and `safety` deliberately do not depend on the `cli`
// feature's optional crates, so `cargo check --no-default-features --lib` still builds
// the protocol core on its own.

pub mod model;
pub mod ops;
pub mod protocol;
pub mod safety;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod config;
#[cfg(feature = "cli")]
pub mod creds;
#[cfg(feature = "cli")]
pub mod db;
#[cfg(feature = "cli")]
pub mod display;
#[cfg(feature = "cli")]
pub mod import;
#[cfg(feature = "cli")]
pub mod mqtt_shell;
#[cfg(feature = "cli")]
pub mod net;
#[cfg(feature = "cli")]
pub mod tui;
#[cfg(feature = "cli")]
pub mod web;
