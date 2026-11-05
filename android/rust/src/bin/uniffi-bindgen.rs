//! Binding generator, invoked by Gradle's `uniffiBindgen` task.
//!
//! Reads the interface from the compiled `.so`'s embedded metadata (`--library`), so
//! there is no `.udl` file to keep in sync with `lib.rs`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
