import contextlib
import os
import threading
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from . import log

# UUID_CLIENT: we connect OUT to the camera (client role).
SAP_UUID_CLIENT = "a49eb41e-cb06-495c-9f4f-bb80a90cdf00"
# UUID_SERVER: the camera connects back IN to us (server role).
SAP_UUID_SERVER = "a49eb41e-cb06-495c-9f4f-aa80a90cdf4a"
PROFILE_PATH_CLIENT = "/gear360/sap1"
PROFILE_PATH_SERVER = "/gear360/sap2"


class SapProfile(dbus.service.Object):
    def __init__(self, bus: dbus.Bus, path: str, label: str) -> None:
        super().__init__(bus, path)
        self.label = label
        self.fd: int | None = None
        self.connection_event = threading.Event()

    @dbus.service.method("org.bluez.Profile1", in_signature="oha{sv}", out_signature="")
    def NewConnection(self, device, fd, properties) -> None:
        connection_fd = fd.take()
        log.step(f"{self.label}: incoming connection (fd={connection_fd})")
        self.fd = connection_fd
        self.connection_event.set()

    @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
    def RequestDisconnection(self, device) -> None:
        log.status(f"[{self.label}] Disconnect requested")

    @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
    def Release(self) -> None:
        log.status(f"[{self.label}] Released")


def setup_dbus() -> tuple[
    dbus.Bus, dbus.Interface, SapProfile, SapProfile, GLib.MainLoop
]:
    """Register both SAP profiles with BlueZ and run a GLib main loop for incoming connections.

    The server profile must advertise an RFCOMM channel: the camera queries our SDP record for
    UUID_SERVER and needs an RFCOMM channel to connect back on. Without `Channel` set, BlueZ only
    lists L2CAP in the protocol descriptor and the camera disconnects.
    """
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    manager = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez"),
        "org.bluez.ProfileManager1",
    )
    client_profile = SapProfile(bus, PROFILE_PATH_CLIENT, "client")
    server_profile = SapProfile(bus, PROFILE_PATH_SERVER, "server")

    client_options = {
        "Name": dbus.String("SAP"),
        "Role": dbus.String("client"),
        "RequireAuthentication": dbus.Boolean(False),
        "RequireAuthorization": dbus.Boolean(False),
        "AutoConnect": dbus.Boolean(False),
    }
    server_options = {
        "Name": dbus.String("SAP"),
        "Role": dbus.String("server"),
        "Channel": dbus.UInt16(0),
        "RequireAuthentication": dbus.Boolean(False),
        "RequireAuthorization": dbus.Boolean(False),
        "AutoConnect": dbus.Boolean(False),
    }
    try:
        manager.RegisterProfile(PROFILE_PATH_CLIENT, SAP_UUID_CLIENT, client_options)
        manager.RegisterProfile(PROFILE_PATH_SERVER, SAP_UUID_SERVER, server_options)
        log.status("Registered client and server (RFCOMM) profiles")
    except dbus.exceptions.DBusException as error:
        log.error(f"Registration failed: {error}")

    loop = GLib.MainLoop()
    loop_thread = threading.Thread(target=loop.run, daemon=True)
    loop_thread.start()
    time.sleep(0.5)

    return bus, manager, client_profile, server_profile, loop


def cleanup_dbus(manager: dbus.Interface, loop: GLib.MainLoop) -> None:
    for path in (PROFILE_PATH_CLIENT, PROFILE_PATH_SERVER):
        with contextlib.suppress(dbus.exceptions.DBusException):
            manager.UnregisterProfile(path)
    loop.quit()


class SapConnection:
    """Owns the BlueZ/D-Bus lifecycle: register profiles, dial the camera, and expose the
    file descriptor of the RFCOMM connection the camera makes back to us."""

    def __init__(self, camera_mac: str) -> None:
        self._device_path = f"/org/bluez/hci0/dev_{camera_mac.replace(':', '_')}"
        self._manager: dbus.Interface | None = None
        self._loop: GLib.MainLoop | None = None
        self.fd: int | None = None

    def open(
        self, connect_delay: float = 5.0, callback_timeout: int = 20
    ) -> int | None:
        bus, self._manager, client_profile, server_profile, self._loop = setup_dbus()
        time.sleep(connect_delay)

        device = dbus.Interface(
            bus.get_object("org.bluez", self._device_path),
            "org.bluez.Device1",
        )
        log.status(f"Calling ConnectProfile({SAP_UUID_CLIENT})...")
        try:
            device.ConnectProfile(SAP_UUID_CLIENT)
        except dbus.exceptions.DBusException as error:
            log.error(f"ConnectProfile failed: {error} (may still work)")

        log.status("Waiting for the camera to connect back...")
        connected = False
        for elapsed in range(callback_timeout):
            if server_profile.connection_event.is_set():
                log.status(f"+{elapsed}s Camera connected back!")
                connected = True
                break
            time.sleep(1)

        # We drive data over the camera's inbound connection; drop our outbound fd.
        if client_profile.fd is not None:
            with contextlib.suppress(OSError):
                os.close(client_profile.fd)

        if not connected:
            log.error("No connect-back from camera")
            return None
        self.fd = server_profile.fd
        return self.fd

    def close(self) -> None:
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.close(self.fd)
        if self._manager is not None and self._loop is not None:
            cleanup_dbus(self._manager, self._loop)
