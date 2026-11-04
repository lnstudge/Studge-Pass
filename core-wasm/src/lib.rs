#![forbid(unsafe_code)]

//! WebAssembly bindings of `studge-core` for the browser extension (Phase 8).

use wasm_bindgen::prelude::*;

/// The version of the Studge Pass core bindings compiled into this module.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
