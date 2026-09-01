//! Library side of the `pam` binary: testable modules behind the thin CLI.
//!
//! The binary in `main.rs` stays a thin shell; everything worth unit-testing
//! lives here.

pub mod caller;

#[cfg(test)]
mod caller_test;
