//! PAM supports only the upstream pure Rust cryptographic implementation.
fn main() {
    assert!(
        std::env::var_os("CARGO_FEATURE_PURE_RUST").is_some(),
        "PAM requires aegis/pure-rust; the native backend is unavailable"
    );
    assert!(
        !(std::env::var_os("CARGO_FEATURE_FORCE_WASM_RELAXED_SIMD").is_some()
            && std::env::var_os("CARGO_FEATURE_FORCE_WASM_STRICT_SIMD").is_some()),
        "The force-wasm-relaxed-simd and force-wasm-strict-simd features are mutually exclusive"
    );
}
