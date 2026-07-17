"""Nautilus extension: right-click "Send with netdrop" to nearby devices.

This is thin glue. All real work lives in the `netdrop` binary:
  * the live device list comes from `netdrop discover --json --cached`
    (served instantly from the running daemon's mDNS cache), and
  * clicking a device runs `netdrop send <device-id> <paths...>`.

Requires the `netdrop` daemon to be running (systemd user service) and
python3-gobject / nautilus-python to be installed.
"""

import json
import shutil
import subprocess

import gi

# Nautilus 48+ ships the 4.1 extension API; older releases expose 4.0. Pick
# whichever the running Nautilus provides.
for _api in ("4.1", "4.0"):
    try:
        gi.require_version("Nautilus", _api)
        break
    except ValueError:
        continue

from gi.repository import GObject, Nautilus  # noqa: E402


def _netdrop_bin():
    return shutil.which("netdrop") or "/usr/bin/netdrop"


def _cached_devices():
    """Return the daemon's cached device list, or [] if unavailable."""
    try:
        out = subprocess.run(
            [_netdrop_bin(), "discover", "--json", "--cached"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if out.returncode != 0:
            return []
        return json.loads(out.stdout or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def _local_paths(files):
    """Local filesystem paths for the selected files (skips remote URIs)."""
    paths = []
    for f in files:
        if f.get_uri_scheme() != "file":
            continue
        location = f.get_location()  # Gio.File
        path = location.get_path() if location else None
        if path:
            paths.append(path)
    return paths


class NetdropMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    """Adds a "Send with netdrop" submenu to the file context menu."""

    def get_file_items(self, files):
        paths = _local_paths(files)
        if not paths:
            return []

        top = Nautilus.MenuItem(
            name="NetdropMenuProvider::send",
            label="Send with netdrop",
            tip="Send the selection to a nearby nsen device",
        )
        submenu = Nautilus.Menu()
        top.set_submenu(submenu)

        devices = _cached_devices()
        if not devices:
            empty = Nautilus.MenuItem(
                name="NetdropMenuProvider::none",
                label="No devices found (is the netdrop daemon running?)",
                sensitive=False,
            )
            submenu.append_item(empty)
            return [top]

        for dev in devices:
            dev_id = dev.get("id", "")
            name = dev.get("name") or dev_id
            item = Nautilus.MenuItem(
                name=f"NetdropMenuProvider::dev::{dev_id}",
                label=name,
                tip=f"Send to {name}",
            )
            item.connect("activate", self._on_send, dev_id, name, paths)
            submenu.append_item(item)

        return [top]

    def _on_send(self, _menu_item, dev_id, name, paths):
        # Fire-and-forget: the daemon prompts the receiver, and netdrop posts a
        # desktop toast on completion, so we don't block Nautilus here.
        try:
            subprocess.Popen(
                [_netdrop_bin(), "send", dev_id, *paths],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            pass
