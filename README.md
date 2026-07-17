# Network Share Tools (ns-tools)

I wanted to transfer files fast, and I was bored so I wrote a tool to do this. There are 3 tools bundled in this repo.

- ns : The original network share bash script I wrote to actually do the job (without encryption)
- nsen : The tool I wrote in rust with encryption so I can use it later
- netdrop : An AirDrop-like layer over nsen — LAN discovery, a post-quantum key exchange (no shared password), and an Accept/Reject prompt, wired into Nautilus

## Building

### MacOS, Linux, BSD
This package is written in rust. You need **rust** and **cargo**.
```shell
cargo build -r
```

Copy and paste the nsen binary into somewhere on your path.

### Windows

Windows users please use WSL with the Linux instructions or use standard rust compilation tools for nsen

## Usage

### Receiver
```shell
nsen recv
```

### Sender
```shell
nsen send <receiver ip> <file/dir path>
```
**Remember to fill in `<receiver ip>` and `<file/dir path>` with actual values.**

For non-interactive use (this is how `netdrop` drives it), the password can be read
from stdin and the port overridden:
```shell
printf '%s\n' "$PASSWORD" | nsen recv --password-stdin --port 4444
printf '%s\n' "$PASSWORD" | nsen send <ip> <path> --password-stdin --port 4444
```

## netdrop — AirDrop-like sharing

`netdrop` wraps `nsen` so devices discover each other automatically and you never
type a shared password. When you send, the two devices run a **post-quantum key
exchange (ML-KEM-768 / CRYSTALS-Kyber, FIPS 203)**; the negotiated secret becomes
the nsen key. The receiver just taps **Accept** or **Reject**. `nsen` still does the
actual encrypted bulk transfer.

### Install and enable the receiver

Install the package (`.rpm`/`.deb` from `make linux`), then enable the background
receiver as a **systemd user service** (a package can't enable a *user* unit for you):
```shell
systemctl --user enable --now netdrop.service
```
Runtime dependencies: `nautilus-python`, `python3-gobject`, `zenity`, `libnotify`.

### Command line

```shell
netdrop discover            # list nearby nsen devices
netdrop send "Kitchen Pi" ~/photo.jpg   # send by device name (or id, or IP)
```

### Nautilus

Right-click a file → **Send with netdrop ▸** and pick a device. The submenu is
populated instantly from the daemon's live device cache.

### Configuration (env vars)

| Variable | Meaning |
| --- | --- |
| `NETDROP_NAME` | Friendly device name shown to peers (default: hostname) |
| `NETDROP_CONTROL_PORT` / `NETDROP_DATA_PORT` | Override the control (4445) / data (4444) ports |
| `NETDROP_AUTO_ACCEPT=1` | Accept incoming transfers without prompting (headless) |
| `NETDROP_NSEN_BIN` | Path to the `nsen` binary (default: `nsen` on `PATH`) |

### Security note

The key exchange is anonymous: ML-KEM protects against passive eavesdroppers, but
Accept/Reject alone does not authenticate the peer, so an active attacker on an
untrusted LAN could impersonate a device. Use it on networks you trust. (`nsen`'s
AES-256-CBC transport is also unauthenticated — unchanged by netdrop.)
