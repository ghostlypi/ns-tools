# netdrop for Android

An Android peer for [netdrop](../README.md) — share-sheet send, foreground-service receive,
same mDNS discovery and ML-KEM-768 key exchange as the desktop tool.

## Status: scaffolding only — not yet buildable

This directory is a **placeholder for Phase 4** of the port roadmap. Nothing here compiles
yet, and that is deliberate: the Android app cannot exist until the desktop code stops
driving `nsen` as a subprocess.

`android/rust` is **excluded from the cargo workspace** (see `exclude` in the root
`Cargo.toml`) so that `cargo build` and `cargo test` at the repo root stay green. Move it
into `members` — alongside a `default-members` list that omits it — when Phase 4 starts.

### Why it can't be built yet

Android 10+ blocks executing binaries from app-writable storage, so the current
architecture cannot be ported as-is:

```
today:    netdrop  ──spawn──>  nsen (separate binary)     ← illegal on Android
target:   netdrop-core  ──call──>  nsen-core (library)
```

`netdrop/src/nsen.rs` writes the transfer password to a child process's stdin and
screen-scrapes `NSEN_PROGRESS` lines off its stdout. That boundary has to become a
function call before any of this directory becomes real work.

### Phase gate

| Phase | Prerequisite | State |
| --- | --- | --- |
| 0 | Test net + path-traversal fix | **done** |
| 1 | `nsen-core` extracted, `nsen` is a thin CLI | **done** |
| 2 | OpenSSL dropped for RustCrypto, wire v2 AEAD | not started |
| 3 | `netdrop-core` extracted, subprocess deleted | not started |
| **4** | **this directory becomes buildable** | **scaffolding** |

Phase 2 is the hard unblock: `openssl = { features = ["vendored"] }` compiles OpenSSL from
C source per ABI and is the single most painful dependency to cross-compile for the NDK.

## Toolchain prerequisites

Not currently installed on the development machine:

```shell
# 1. cmdline-tools (for sdkmanager) — install via Android Studio's SDK Manager,
#    or drop the zip into $ANDROID_HOME/cmdline-tools/latest/
sdkmanager "ndk;27.2.12479018" "platforms;android-35"

# 2. Rust targets — only x86_64-unknown-linux-gnu is installed today
rustup target add aarch64-linux-android x86_64-linux-android

# 3. The NDK bridge
cargo install cargo-ndk
```

**NDK r27 or newer is required, not optional.** Android 15+ devices need 16 KB-aligned
shared libraries; r27+ emits them via `-Wl,-z,max-page-size=16384`. An older NDK silently
produces a `.so` that fails to load on a Pixel 8+ running Android 15.

Already present: Android SDK at `~/Android/Sdk` (platforms android-35, android-36.1;
build-tools 35.0.0/36.1.0/37.0.0; `adb`), JDK 21.

## Design decisions already made

Recorded here so they don't get relitigated when Phase 4 starts.

**UniFFI, not hand-written JNI.** Traffic is bidirectional and callback-heavy — progress
ticks, offer prompts, peer-list deltas, SAF file handles. By hand that means managing
`JavaVM*`, `AttachCurrentThread` per worker thread, global-ref lifetimes, and
`DeleteLocalRef` discipline in a loop firing ~10×/sec. UniFFI generates all of it.

**Callbacks never block.** `on_offer` returns immediately and the app later calls
`respond_to_offer(transfer_id, accept)`. UniFFI callbacks run synchronously on the calling
Rust thread; a blocking prompt would park the receiver thread inside a JNI call while
Kotlin waits on a latch — and an ANR if it ever happens on the main thread.

**mDNS stays in Rust (`mdns-sd`), with a `MulticastLock` held from Kotlin.** Without the
lock, Android silently drops multicast and discovery appears to work while finding
nothing. The alternative — `NsdManager` in Kotlin — would fork the TXT-record and
address-selection logic (`netdrop/src/discovery.rs:184-214`) into two implementations that
must agree. The `Discovery` trait stays as a seam in case a specific OEM Wi-Fi stack
misbehaves.

**Two ABIs only**: `arm64-v8a` and `x86_64` (emulator). `armeabi-v7a`/`x86` are dead weight
for a personal sideload and each adds ~3 MB.

**`zstdmt` off for Android.** `zstd-sys` cross-compiles via `cc` against the NDK and the
multithread build pulls pthread specifics — the likeliest thing to block Phase 4. Mobile
has few cores and a battery, so single-threaded zstd is right regardless.

**Foreground service type is `connectedDevice`, not `dataSync`.** Android 15 caps
`dataSync` services at 6 hours per 24-hour period, after which the system stops them and
you cannot restart until the window resets.

**Time-boxed discoverability, not a daemon.** There is no Android equivalent of
`packaging/netdrop.service`, and chasing one burns a week on untestable OEM workarounds.
The receiver is started by an explicit user action and runs a visible countdown (30 min
default, extendable). This is AirDrop's own model, it is better security than always-on,
and it turns a platform limitation into a deliberate feature.

The honest promise, which should be the literal copy in the app:

> netdrop is discoverable while this notification is showing.

**Manual IP entry is required, not a nicety.** Guest and public Wi-Fi commonly enable
client isolation, which kills mDNS *and* the direct TCP. It also covers L3 VPNs such as
WireGuard, where multicast never traverses the tunnel but the unicast transfer works fine.

## Layout

```
android/
├── README.md              this file
├── rust/                  UniFFI bindings crate (cdylib) — Phase 4
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs         the FFI contract; stubbed until netdrop-core exists
│       └── bin/uniffi-bindgen.rs
└── app/                   Gradle/Kotlin app — Phase 4-6
    ├── build.gradle.kts
    ├── settings.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        └── kotlin/dev/ghostlypi/netdrop/
```

## Building, once Phase 4 lands

```shell
make android          # cargo-ndk per ABI, then gradlew assembleRelease
make android-install  # adb install -r
```
