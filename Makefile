CARGO       := cargo
CROSS       := CROSS_CONTAINER_ENGINE=podman CROSS_TARGET_DIR=$(CURDIR)/target cross
# Pinned to a stable release published at ziglang.org/download/
ZIG_VERSION := 0.14.0

LINUX_X64   := x86_64-unknown-linux-gnu
LINUX_ARM64 := aarch64-unknown-linux-gnu
MACOS_X64   := x86_64-apple-darwin
MACOS_ARM64 := aarch64-apple-darwin
WIN_X64     := x86_64-pc-windows-gnu
WIN_ARM64   := aarch64-pc-windows-msvc

OUT := dist

.PHONY: all linux macos windows clean setup setup-ci \
        linux-x64 linux-arm64 \
        macos-x64 macos-arm64 \
        windows-x64 windows-arm64

# Local builds (Fedora): Linux x86_64+arm64 and Windows x86_64.
# macOS and Windows arm64 require platform-native toolchains — use CI for those.
all: linux windows-x64

linux:   linux-x64 linux-arm64
macos:   macos-x64 macos-arm64
windows: windows-x64 windows-arm64

# ── Linux ──────────────────────────────────────────────────────────────────────

linux-x64:
	$(CARGO) build --release --target $(LINUX_X64)
	$(CARGO) deb   --no-build --target $(LINUX_X64)
	$(CARGO) generate-rpm    --target $(LINUX_X64)
	@mkdir -p $(OUT)
	cp target/$(LINUX_X64)/release/nsen           $(OUT)/nsen-$(LINUX_X64)
	cp target/$(LINUX_X64)/debian/*.deb           $(OUT)/
	cp target/$(LINUX_X64)/generate-rpm/*.rpm     $(OUT)/

linux-arm64:
	$(CARGO) zigbuild --release --target $(LINUX_ARM64)
	$(CARGO) deb   --no-build --no-strip --target $(LINUX_ARM64)
	$(CARGO) generate-rpm    --target $(LINUX_ARM64)
	@mkdir -p $(OUT)
	cp target/$(LINUX_ARM64)/release/nsen         $(OUT)/nsen-$(LINUX_ARM64)
	cp target/$(LINUX_ARM64)/debian/*.deb         $(OUT)/
	cp target/$(LINUX_ARM64)/generate-rpm/*.rpm   $(OUT)/

# ── macOS ──────────────────────────────────────────────────────────────────────
# Native cargo works on macOS runners (Apple SDK is present).
# From Linux these targets fail — use CI or osxcross.

macos-x64:
	@uname | grep -q Darwin || { \
		echo "ERROR: macOS builds require running on macOS (Apple SDK needed)."; \
		echo "       Push a tag to build via CI: git tag v<ver> && git push origin v<ver>"; \
		exit 1; }
	$(CARGO) build --release --target $(MACOS_X64)
	@mkdir -p $(OUT)
	cp target/$(MACOS_X64)/release/nsen           $(OUT)/nsen-$(MACOS_X64)

macos-arm64:
	@uname | grep -q Darwin || { \
		echo "ERROR: macOS builds require running on macOS (Apple SDK needed)."; \
		echo "       Push a tag to build via CI: git tag v<ver> && git push origin v<ver>"; \
		exit 1; }
	$(CARGO) build --release --target $(MACOS_ARM64)
	@mkdir -p $(OUT)
	cp target/$(MACOS_ARM64)/release/nsen         $(OUT)/nsen-$(MACOS_ARM64)

# ── Windows ────────────────────────────────────────────────────────────────────
# x86_64 uses MinGW (gnu ABI). aarch64 uses MSVC (Windows runners only).

windows-x64:
	$(CARGO) build --release --target $(WIN_X64)
	@mkdir -p $(OUT)
	cp target/$(WIN_X64)/release/nsen.exe         $(OUT)/nsen-$(WIN_X64).exe

windows-arm64:
	$(CARGO) build --release --target $(WIN_ARM64)
	@mkdir -p $(OUT)
	cp target/$(WIN_ARM64)/release/nsen.exe       $(OUT)/nsen-$(WIN_ARM64).exe

# ── Utility ────────────────────────────────────────────────────────────────────

clean:
	$(CARGO) clean
	rm -rf $(OUT)

# ── Local setup (Fedora 43) ────────────────────────────────────────────────────

setup:
	@echo "==> Adding Rust targets..."
	rustup target add $(LINUX_ARM64) $(MACOS_X64) $(MACOS_ARM64) $(WIN_X64) $(WIN_ARM64)
	@echo "==> Installing system packages..."
	sudo dnf install -y \
		gcc make \
		perl perl-FindBin perl-IPC-Cmd perl-File-Compare perl-File-Copy \
		gcc-aarch64-linux-gnu \
		mingw64-gcc \
		zig \
		podman
	@echo "==> Installing Cargo tools..."
	cargo install cargo-deb cargo-generate-rpm cargo-zigbuild
	cargo install cross --git https://github.com/cross-rs/cross
	@echo "==> Setup complete. Run 'make all' to build everything."

# ── CI setup (GitHub Actions) ─────────────────────────────────────────────────
# Detects Ubuntu (Linux runners) vs macOS runners automatically.

setup-ci:
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "==> macOS CI setup..."; \
		rustup target add $(MACOS_X64) $(MACOS_ARM64); \
		cargo install cargo-zigbuild; \
	else \
		echo "==> Linux CI setup (Ubuntu)..."; \
		sudo apt-get update -q; \
		sudo apt-get install -y gcc make perl mingw-w64; \
		rustup target add $(LINUX_ARM64) $(WIN_X64); \
		cargo install cargo-deb cargo-generate-rpm cargo-zigbuild; \
	fi
	@echo "==> CI setup complete."
