#!/usr/bin/env python3
"""
Remotely control a Victron Phoenix (Smart) Inverter over BLE GATT using a
BleuIO Pro USB dongle: switch power mode (on/eco/off) and write individual
Eco mode settings registers.

This is a DIFFERENT protocol path than victron_bleuio_scanner.py /
victron_bleuio_known_devices.py. Those read the public, Victron-documented
"Instant Readout" BLE advertisement (broadcast only, no connection). This
script instead opens a real GATT connection to the inverter -- the same
thing the VictronConnect app does to control it -- which requires Bluetooth
pairing and is NOT officially documented or supported by Victron.

The underlying wire format was reverse-engineered from real VictronConnect
<-> Phoenix Inverter BLE packet captures: the power-mode command by a third
party (https://github.com/Olen/VictronConnect, phoenix.py), and the settings
register-write format from live captures of this specific inverter's Eco
mode settings being changed in the app (done in this session, via a Nordic
nRF Sniffer for Bluetooth LE + Wireshark). All of them write to the same
"command" characteristic (306b0003) using a general register-write frame:

    06 03 82 19 <register-id, 2 bytes LE> <type byte> <value, N bytes LE>

    type 0x41 -> 1-byte value
    type 0x42 -> 2-byte value

Confirmed registers:
    0x0002  power mode (1 byte): 0x02=on, 0x05=eco, 0x04=off
    0x0622  Eco mode shutdown power, VA (2 bytes, unscaled)
    0x0722  Eco mode wake-up power, VA (2 bytes, unscaled)
    0x0aeb  Eco mode search interval, seconds (2 bytes, unscaled)
    0x10eb  Eco mode search time, seconds (1 byte, raw value = round(seconds * 50);
            max representable ~5.1s since it's a single byte)
    0x3002  AC output voltage, V (2 bytes, raw value = round(volts * 100)).
            Valid range 210-245V in 1V steps, default 230V.
    0x1022  Low battery / shutdown voltage, V (2 bytes, raw value = round(volts * 100)).
            Valid range 9.30-17.00V in 0.01V steps.
    0x2003  Low battery alarm voltage, V (2 bytes, raw value = round(volts * 100)).
            Valid range 9.30-17.00V in 0.01V steps.
    0x2103  Low battery alarm clear ("charge detect") voltage, V (2 bytes,
            raw value = round(volts * 100)). Valid range 9.30-17.00V in
            0.01V steps, default 14.00V.
    0x03eb  AC output frequency (1 byte, boolean): 0x00=60Hz, 0x01=50Hz
    0xbaeb  Dynamic cutoff voltage enabled (1 byte, boolean): 0x01=on, 0x00=off
    0x0010  Battery capacity, Ah (2 bytes, unscaled)
    0xb2eb  Dynamic cutoff voltage factor at 0.005A, V (2 bytes, raw = round(volts * 1000)).
            Valid range 0.00-100.00V in 0.01V steps.
    0xb3eb  Dynamic cutoff voltage factor at 0.250A, V (2 bytes, raw = round(volts * 1000)).
            Valid range 0.00-100.00V in 0.01V steps.
    0xb4eb  Dynamic cutoff voltage factor at 0.700A, V (2 bytes, raw = round(volts * 1000)).
            Valid range 0.00-100.00V in 0.01V steps.
    0xb5eb  Dynamic cutoff voltage factor at 2.000A, V (2 bytes, raw = round(volts * 1000)).
            Valid range 0.00-100.00V in 0.01V steps.
    0xa301  Settings lock code (4 bytes, raw = the 8-digit code as a plain
            integer, e.g. "72727272" -> 72727272). Confirmed via three live
            captures, each setting a different 8-digit code.
    0xa001  The same lock code, paired with a timestamp (8 bytes: the code as
            a 4-byte LE uint32 in the low half, current Unix time -- seconds
            since epoch -- as a 4-byte LE uint32 in the high half).
            VictronConnect always writes this register first, then 0xa301,
            whenever the lock code is set. The timestamp's exact purpose on
            the device side is unclear, but across two live captures it
            tracked real elapsed wall-clock time almost exactly, which rules
            out a nonce or a checksum of the code.

Unlocking (removing the code) writes only 0xa001 -- with the low 4 bytes set
to the sentinel 0xFFFFFFFF instead of a real code, and the high 4 bytes the
current Unix timestamp as usual. 0xa301 is left untouched. VictronConnect's
own confirmation prompt (re-entering the existing code before unlocking) is
checked locally in the app; the code you type is never part of this write.

"Battery type" (Gel/AGM, OPzS/OPzV, Smart Lithium, Custom) is not its own
register -- VictronConnect just writes the four dynamic-cutoff-curve
registers above with fixed values per preset, and shows "Custom" whenever
the curve doesn't match a known preset. --set-battery-type sends the
matching bundle of four writes for you; see BATTERY_TYPE_PRESETS.

The voltage/frequency registers above are safety-relevant: they affect what's
plugged into the inverter's output right now, or when the inverter cuts off
from the battery. Change them in small steps and double check the result in
VictronConnect, the same way these were discovered.

After a settings write, VictronConnect was also observed sending a write of
register 0x99eb = 1 (1 byte) shortly after -- this looks like a generic
"apply/commit" signal sent after any settings change rather than a distinct
setting itself. It was NOT required in our own direct tests (the inverter
applied 0x0722 immediately without it), so this script does not send it,
but if a register write here doesn't seem to stick, that's worth trying.

Other settings have unknown register IDs -- guessing them is not safe; each
new one needs its own verified packet capture before being added here.

"Relay mode" specifically is NOT investigated, and can't be with this
approach: it refers to the inverter's physical remote on/off input (screw
terminals), not an app-settable value. Live-testing it (open vs. closed
circuit on that input) showed the inverter stop responding entirely rather
than exposing any distinct state over BLE -- consistent with it being a
hardware power switch -- but this has not been confirmed against
VictronConnect itself, since the app has no control or display for it to
compare against. Treat this as unverified, not resolved.

This is unofficial, unsupported, and could put the device into an
unexpected state. Use it on your own equipment, at your own risk, and only
after you understand what it does.

Troubleshooting: "Could not connect" / stuck at "Trying to connect..."
------------------------------------------------------------------------
The inverter only accepts one connected BLE central at a time. If
VictronConnect (on a phone or on this Mac) still has an active connection
or background session with it, this script's connection attempt will
fail or hang. Fully close VictronConnect everywhere (swipe it away on
phones, quit it on Mac -- backgrounding isn't enough) before running this.

How it works
------------
  1. Connects to the inverter's MAC address over GATT (AT+GAPCONNECT).
  2. Pairs and bonds with it using the device's Bluetooth PIN
     (AT+GAPPAIR=BOND + AT+ENTERPASSKEY). You can find the PIN printed on
     a sticker on the inverter, or in VictronConnect under the device's
     Bluetooth pairing screen.
  3. Discovers GATT services/characteristics (AT+GETSERVICES) and locates
     the handles for the vendor service's control characteristics -- this
     is done dynamically by UUID, not hardcoded, since ATT handles can
     differ between devices/firmware versions.
  4. Replays the exact init/handshake byte sequence captured from a real
     VictronConnect session (writes to the "control" characteristic
     306b0002) -- this appears to be required before the device will
     accept any command.
  5. Writes the requested command to the "command" characteristic 306b0003.

Requirements
------------
    pip install pyserial

Usage
-----
    # Power mode
    python3 victron_inverter_power_control.py \\
        --mac AA:BB:CC:DD:EE:FF --addr-type 1 --pin 123456 --set eco

    # Eco mode settings
    python3 victron_inverter_power_control.py --config inverter.json --set-eco-wakeup-power 14
    python3 victron_inverter_power_control.py --config inverter.json --set-eco-shutdown-power 30
    python3 victron_inverter_power_control.py --config inverter.json --set-eco-search-interval 8
    python3 victron_inverter_power_control.py --config inverter.json --set-eco-search-time 0.26

    # Safety-relevant settings (change with care, see docstring above)
    python3 victron_inverter_power_control.py --config inverter.json --set-ac-voltage 231
    python3 victron_inverter_power_control.py --config inverter.json --set-low-battery-shutdown 9.31
    python3 victron_inverter_power_control.py --config inverter.json --set-low-battery-alarm 10.91
    python3 victron_inverter_power_control.py --config inverter.json --set-low-battery-alarm-clear 14.01
    python3 victron_inverter_power_control.py --config inverter.json --set-ac-frequency 50
    python3 victron_inverter_power_control.py --config inverter.json --set-dynamic-cutoff on
    python3 victron_inverter_power_control.py --config inverter.json --set-battery-capacity 166
    python3 victron_inverter_power_control.py --config inverter.json --set-dyn-cutoff-0005 12.01
    python3 victron_inverter_power_control.py --config inverter.json --set-dyn-cutoff-0250 11.26
    python3 victron_inverter_power_control.py --config inverter.json --set-dyn-cutoff-0700 10.56
    python3 victron_inverter_power_control.py --config inverter.json --set-dyn-cutoff-2000 10.01
    python3 victron_inverter_power_control.py --config inverter.json --set-battery-type gel_agm
    python3 victron_inverter_power_control.py --config inverter.json --set-lock-code 12345678
    python3 victron_inverter_power_control.py --config inverter.json --unlock-settings

    # or store address/PIN in a small JSON file and reuse it:
    python3 victron_inverter_power_control.py --config inverter.json --set on

inverter.json format:
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "addr_type": 1,
      "pin": "123456"
    }

By default the script prints what it's about to do and asks for a typed
"yes" confirmation before sending the write. Pass --yes to skip that (e.g.
for use in your own automation/cron), but understand that at that point
nothing stops it from actually changing your inverter's behavior.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from typing import Optional

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    sys.exit("Missing dependency 'pyserial'. Install it with: pip install pyserial")


BLEUIO_HWID_MARKERS = ("VID:PID=2DCF:6001", "VID:PID=2DCF:6002")

# Reverse-engineered from a VictronConnect <-> Phoenix Inverter BLE capture.
# Source: https://github.com/Olen/VictronConnect (phoenix.py)
SERVICE_UUID = "306b0001-b081-4037-83dc-e59fcc3cdfd0"
CONTROL_CHAR_UUID = "306b0002-b081-4037-83dc-e59fcc3cdfd0"  # keep-alive / init
COMMAND_CHAR_UUID = "306b0003-b081-4037-83dc-e59fcc3cdfd0"  # power-mode command

INIT_SEQUENCE = [
    (CONTROL_CHAR_UUID, "FA80FF"),
    (CONTROL_CHAR_UUID, "F980"),
    (CONTROL_CHAR_UUID, "01"),
    (COMMAND_CHAR_UUID, "01"),
    (COMMAND_CHAR_UUID, "0300"),
    (COMMAND_CHAR_UUID, "060082189342102703010303"),
    (CONTROL_CHAR_UUID, "F941"),
]

def build_register_write(register_id: int, value: int, value_size: int) -> str:
    """Build a '06 03 82 19 <reg LE> <type> <value LE>' register-write frame.

    type byte encodes the value width: 0x40 + value_size (confirmed for
    value_size 1 -> 0x41 and 2 -> 0x42; other sizes are unverified).
    """
    type_byte = 0x40 + value_size
    frame = (
        bytes([0x06, 0x03, 0x82, 0x19])
        + register_id.to_bytes(2, "little")
        + bytes([type_byte])
        + value.to_bytes(value_size, "little")
    )
    return frame.hex()


# Register 0x0002 (power mode): confirmed via github.com/Olen/VictronConnect phoenix.py
POWER_MODE_REGISTER = 0x0002
POWER_MODE_VALUES = {"on": 0x02, "eco": 0x05, "off": 0x04}
POWER_MODE_COMMANDS = {
    mode: build_register_write(POWER_MODE_REGISTER, value, 1)
    for mode, value in POWER_MODE_VALUES.items()
}

# Eco mode settings registers: confirmed via live packet captures of this
# specific inverter's Eco mode settings being changed in VictronConnect.
ECO_WAKEUP_POWER_REGISTER = 0x0722       # VA, 2 bytes, unscaled
ECO_SHUTDOWN_POWER_REGISTER = 0x0622     # VA, 2 bytes, unscaled
ECO_SEARCH_INTERVAL_REGISTER = 0x0aeb    # seconds, 2 bytes, unscaled
ECO_SEARCH_TIME_REGISTER = 0x10eb        # seconds, 1 byte, raw = round(seconds * 50)

# Safety-relevant registers: also confirmed via live packet capture. All are
# 2 bytes, raw value = round(volts * 100).
AC_VOLTAGE_REGISTER = 0x3002
AC_VOLTAGE_MIN = 210  # V, matches this inverter's MinVoltageSetpoint
AC_VOLTAGE_MAX = 245  # V, matches this inverter's MaxVoltageSetpoint; default is 230V
LOW_BATTERY_SHUTDOWN_REGISTER = 0x1022
LOW_BATTERY_SHUTDOWN_MIN = 9.30   # V
LOW_BATTERY_SHUTDOWN_MAX = 17.00  # V, in 0.01V steps
LOW_BATTERY_ALARM_REGISTER = 0x2003
LOW_BATTERY_ALARM_MIN = 9.30   # V
LOW_BATTERY_ALARM_MAX = 17.00  # V, in 0.01V steps
LOW_BATTERY_ALARM_CLEAR_REGISTER = 0x2103
LOW_BATTERY_ALARM_CLEAR_MIN = 9.30    # V
LOW_BATTERY_ALARM_CLEAR_MAX = 17.00   # V, in 0.01V steps; default is 14.00V

# AC frequency register: confirmed via two live packet captures, one for
# each direction (50Hz->60Hz and 60Hz->50Hz).
AC_FREQUENCY_REGISTER = 0x03eb
AC_FREQUENCY_VALUES = {60: 0x00, 50: 0x01}

# Dynamic cutoff voltage enabled register: confirmed via two live packet
# captures, one for each direction (off->on and on->off).
DYNAMIC_CUTOFF_REGISTER = 0xbaeb
DYNAMIC_CUTOFF_VALUES = {"on": 0x01, "off": 0x00}

# Battery capacity register: confirmed via live packet capture.
BATTERY_CAPACITY_REGISTER = 0x0010  # Ah, 2 bytes, unscaled

# Dynamic cutoff voltage curve factors: also confirmed via live packet
# capture. All are 2 bytes, raw value = round(volts * 1000).
# Valid range 0.00-100.00V in 0.01V steps (per VictronConnect's own input
# limits, confirmed by the user against the real app).
DYN_CUTOFF_FACTOR_0005_REGISTER = 0xb2eb
DYN_CUTOFF_FACTOR_0250_REGISTER = 0xb3eb
DYN_CUTOFF_FACTOR_0700_REGISTER = 0xb4eb
DYN_CUTOFF_FACTOR_2000_REGISTER = 0xb5eb
DYN_CUTOFF_FACTOR_MIN = 0.00
DYN_CUTOFF_FACTOR_MAX = 100.00

# "Battery type" presets: each is just the bundle of dynamic-cutoff-curve
# values VictronConnect sends when you pick that preset in the app -- there
# is no separate battery-type register. Confirmed via live packet capture
# (each preset selection was observed writing exactly these four values).
BATTERY_TYPE_PRESETS = {
    "gel_agm": [
        (DYN_CUTOFF_FACTOR_0005_REGISTER, 12.000),
        (DYN_CUTOFF_FACTOR_0250_REGISTER, 11.650),
        (DYN_CUTOFF_FACTOR_0700_REGISTER, 11.400),
        (DYN_CUTOFF_FACTOR_2000_REGISTER, 11.200),
    ],
    "opzs_opzv": [
        (DYN_CUTOFF_FACTOR_0005_REGISTER, 12.000),
        (DYN_CUTOFF_FACTOR_0250_REGISTER, 11.250),
        (DYN_CUTOFF_FACTOR_0700_REGISTER, 10.550),
        (DYN_CUTOFF_FACTOR_2000_REGISTER, 10.000),
    ],
    "smart_lithium": [
        (DYN_CUTOFF_FACTOR_0005_REGISTER, 13.000),
        (DYN_CUTOFF_FACTOR_0250_REGISTER, 12.500),
        (DYN_CUTOFF_FACTOR_0700_REGISTER, 12.300),
        (DYN_CUTOFF_FACTOR_2000_REGISTER, 12.000),
    ],
}

# Settings lock code registers: confirmed via three live packet captures,
# each setting a different 8-digit code. VictronConnect writes 0xa001 (code +
# timestamp) first, then 0xa301 (code alone) -- see the module docstring.
LOCK_CODE_TIMESTAMPED_REGISTER = 0xa001  # 8 bytes: code (low 4B LE) + unix time (high 4B LE)
LOCK_CODE_REGISTER = 0xa301              # 4 bytes: code alone
UNLOCK_SENTINEL = 0xFFFFFFFF             # written to the low 4 bytes of 0xa001 to unlock

SERVICE_LINE_RE = re.compile(r"^([0-9a-fA-F]{4})\s+----\s+([0-9a-fA-F-]+)\s*$")


def find_dongle_port() -> Optional[str]:
    for port in list_ports.comports():
        hwid = port.hwid or ""
        if any(marker in hwid for marker in BLEUIO_HWID_MARKERS):
            return port.device
    return None


class BleuIOGattClient:
    def __init__(self, port: Optional[str], baud: int, verbose: bool = False):
        self.port_name = port or find_dongle_port()
        if not self.port_name:
            sys.exit(
                "No BleuIO dongle found on any USB serial port. "
                "Plug it in, or pass --port explicitly."
            )
        self.verbose = verbose
        try:
            self.ser = serial.Serial(self.port_name, baud, timeout=1)
        except serial.SerialException as e:
            sys.exit(f"Could not open {self.port_name}: {e}")
        time.sleep(0.3)
        self.ser.reset_input_buffer()

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def send(self, cmd: str, wait: float = 2.0):
        if self.verbose:
            print(f">> {cmd}")
        self.ser.reset_input_buffer()
        self.ser.write((cmd + "\r\n").encode())
        deadline = time.time() + wait
        lines = []
        while time.time() < deadline or self.ser.in_waiting:
            raw = self.ser.readline()
            if not raw:
                if time.time() >= deadline:
                    break
                continue
            line = raw.decode("utf-8", errors="ignore").strip()
            if line:
                if self.verbose:
                    print(f"<< {line}")
                lines.append(line)
        return lines

    def connect(self, mac: str, addr_type: int) -> bool:
        self.send("AT+CENTRAL")
        self.send("AT+GAPIOCAP=2")  # Keyboard Only -> enables passkey-entry pairing
        lines = self.send(f"AT+GAPCONNECT=[{addr_type}]{mac}", wait=6.0)
        return any("CONNECTED" in l for l in lines)

    def pair(self, pin: str) -> bool:
        lines = self.send("AT+GAPPAIR=BOND", wait=4.0)
        if any("PASSKEY_REQUEST" in l for l in lines):
            lines += self.send(f"AT+ENTERPASSKEY={pin}", wait=6.0)
        return any("PAIRING SUCCESS" in l for l in lines)

    def discover_handles(self) -> dict:
        """Run AT+GETSERVICES and map characteristic UUID -> ATT value handle."""
        lines = self.send("AT+GETSERVICES", wait=6.0)
        handles = {}
        for line in lines:
            m = SERVICE_LINE_RE.match(line.strip())
            if m:
                handle, uuid = m.groups()
                handles[uuid.lower()] = handle
        return handles

    def write_handle(self, handle: str, hex_data: str, wait: float = 1.5):
        return self.send(f"AT+GATTCWRITEB={handle} {hex_data}", wait=wait)

    def disconnect(self):
        self.send("AT+GAPDISCONNECT", wait=2.0)


def load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Switch a Victron Phoenix Inverter's power mode (on/eco/off) "
            "over BLE GATT using a BleuIO Pro dongle. Unofficial protocol -- "
            "see the module docstring before using this on real equipment."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", help="JSON file with mac/addr_type/pin (see docstring)")
    parser.add_argument("--mac", help="Inverter MAC address, e.g. AA:BB:CC:DD:EE:FF")
    parser.add_argument("--addr-type", type=int, help="BLE address type (0=public, 1=random)")
    parser.add_argument("--pin", help="Bluetooth pairing PIN for the inverter")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--set", choices=sorted(POWER_MODE_COMMANDS), help="Power mode to switch to")
    action.add_argument("--set-eco-wakeup-power", type=int, metavar="VA", help="Eco mode wake-up power threshold, in VA (0-65535)")
    action.add_argument("--set-eco-shutdown-power", type=int, metavar="VA", help="Eco mode shutdown power threshold, in VA (0-65535)")
    action.add_argument("--set-eco-search-interval", type=int, metavar="SECONDS", help="Eco mode search interval, in seconds (0-65535)")
    action.add_argument("--set-eco-search-time", type=float, metavar="SECONDS", help="Eco mode search time, in seconds (0-5.1, encoded in 0.02s steps)")
    action.add_argument("--set-ac-voltage", type=float, metavar="VOLTS", help="AC output voltage, in whole volts, 210-245 (default 230; safety-relevant, see docstring)")
    action.add_argument("--set-low-battery-shutdown", type=float, metavar="VOLTS", help="Low battery shutdown voltage, in volts, 9.30-17.00 (safety-relevant, see docstring)")
    action.add_argument("--set-low-battery-alarm", type=float, metavar="VOLTS", help="Low battery alarm voltage, in volts, 9.30-17.00 (safety-relevant, see docstring)")
    action.add_argument("--set-low-battery-alarm-clear", type=float, metavar="VOLTS", help="Low battery alarm clear voltage, in volts, 9.30-17.00, default 14.00 (safety-relevant, see docstring)")
    action.add_argument("--set-ac-frequency", type=int, choices=sorted(AC_FREQUENCY_VALUES), help="AC output frequency, in Hz (safety-relevant, see docstring)")
    action.add_argument("--set-dynamic-cutoff", choices=sorted(DYNAMIC_CUTOFF_VALUES), help="Dynamic cutoff voltage enabled, on or off")
    action.add_argument("--set-battery-capacity", type=int, metavar="AH", help="Battery capacity, in Ah (0-65535)")
    action.add_argument("--set-dyn-cutoff-0005", type=float, metavar="VOLTS", help="Dynamic cutoff voltage factor at 0.005A, in volts, 0.00-100.00")
    action.add_argument("--set-dyn-cutoff-0250", type=float, metavar="VOLTS", help="Dynamic cutoff voltage factor at 0.250A, in volts, 0.00-100.00")
    action.add_argument("--set-dyn-cutoff-0700", type=float, metavar="VOLTS", help="Dynamic cutoff voltage factor at 0.700A, in volts, 0.00-100.00")
    action.add_argument("--set-dyn-cutoff-2000", type=float, metavar="VOLTS", help="Dynamic cutoff voltage factor at 2.000A, in volts, 0.00-100.00")
    action.add_argument("--set-battery-type", choices=sorted(BATTERY_TYPE_PRESETS), help="Battery type preset (sends the matching dynamic cutoff curve, see docstring)")
    action.add_argument("--set-lock-code", metavar="CODE", help="Settings lock code, exactly 8 digits (e.g. 12345678)")
    action.add_argument("--unlock-settings", action="store_true", help="Remove the settings lock code")
    parser.add_argument("--port", help="Serial port of the BleuIO dongle (default: auto-detect)")
    parser.add_argument("--baud", type=int, default=115200, help="Serial baud rate (default: 115200)")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt")
    parser.add_argument("--verbose", action="store_true", help="Print raw AT command traffic to/from the dongle")
    args = parser.parse_args()

    cfg = load_config(args.config)
    mac = args.mac or cfg.get("mac")
    addr_type = args.addr_type if args.addr_type is not None else cfg.get("addr_type")
    pin = args.pin or cfg.get("pin")

    if not mac or addr_type is None or not pin:
        sys.exit(
            "Need --mac, --addr-type and --pin (or --config pointing at a JSON "
            "file with those fields). See --help for the config file format."
        )

    def require_range(value, lo, hi, name):
        if not lo <= value <= hi:
            sys.exit(f"{name} must be between {lo} and {hi}")

    if args.set:
        action_desc = f"switch its power mode to '{args.set.upper()}'"
        command_hex = POWER_MODE_COMMANDS[args.set]
    elif args.set_eco_wakeup_power is not None:
        require_range(args.set_eco_wakeup_power, 0, 0xFFFF, "--set-eco-wakeup-power")
        action_desc = f"set its Eco mode wake-up power to {args.set_eco_wakeup_power} VA"
        command_hex = build_register_write(ECO_WAKEUP_POWER_REGISTER, args.set_eco_wakeup_power, 2)
    elif args.set_eco_shutdown_power is not None:
        require_range(args.set_eco_shutdown_power, 0, 0xFFFF, "--set-eco-shutdown-power")
        action_desc = f"set its Eco mode shutdown power to {args.set_eco_shutdown_power} VA"
        command_hex = build_register_write(ECO_SHUTDOWN_POWER_REGISTER, args.set_eco_shutdown_power, 2)
    elif args.set_eco_search_interval is not None:
        require_range(args.set_eco_search_interval, 0, 0xFFFF, "--set-eco-search-interval")
        action_desc = f"set its Eco mode search interval to {args.set_eco_search_interval} s"
        command_hex = build_register_write(ECO_SEARCH_INTERVAL_REGISTER, args.set_eco_search_interval, 2)
    elif args.set_eco_search_time is not None:
        raw = round(args.set_eco_search_time * 50)
        require_range(raw, 0, 0xFF, "--set-eco-search-time (encoded value)")
        action_desc = f"set its Eco mode search time to {args.set_eco_search_time} s (raw={raw})"
        command_hex = build_register_write(ECO_SEARCH_TIME_REGISTER, raw, 1)
    else:
        def voltage_command(volts, register, name):
            raw = round(volts * 100)
            require_range(raw, 0, 0xFFFF, f"{name} (encoded value)")
            return build_register_write(register, raw, 2)

        if args.set_ac_voltage is not None:
            require_range(args.set_ac_voltage, AC_VOLTAGE_MIN, AC_VOLTAGE_MAX, "--set-ac-voltage")
            if args.set_ac_voltage != round(args.set_ac_voltage):
                sys.exit("--set-ac-voltage must be a whole number of volts (1V steps)")
            action_desc = f"set its AC output voltage to {args.set_ac_voltage} V"
            command_hex = voltage_command(args.set_ac_voltage, AC_VOLTAGE_REGISTER, "--set-ac-voltage")
        elif args.set_low_battery_shutdown is not None:
            require_range(args.set_low_battery_shutdown, LOW_BATTERY_SHUTDOWN_MIN, LOW_BATTERY_SHUTDOWN_MAX, "--set-low-battery-shutdown")
            action_desc = f"set its low battery shutdown voltage to {args.set_low_battery_shutdown} V"
            command_hex = voltage_command(args.set_low_battery_shutdown, LOW_BATTERY_SHUTDOWN_REGISTER, "--set-low-battery-shutdown")
        elif args.set_low_battery_alarm is not None:
            require_range(args.set_low_battery_alarm, LOW_BATTERY_ALARM_MIN, LOW_BATTERY_ALARM_MAX, "--set-low-battery-alarm")
            action_desc = f"set its low battery alarm voltage to {args.set_low_battery_alarm} V"
            command_hex = voltage_command(args.set_low_battery_alarm, LOW_BATTERY_ALARM_REGISTER, "--set-low-battery-alarm")
        elif args.set_low_battery_alarm_clear is not None:
            require_range(args.set_low_battery_alarm_clear, LOW_BATTERY_ALARM_CLEAR_MIN, LOW_BATTERY_ALARM_CLEAR_MAX, "--set-low-battery-alarm-clear")
            action_desc = f"set its low battery alarm clear voltage to {args.set_low_battery_alarm_clear} V"
            command_hex = voltage_command(args.set_low_battery_alarm_clear, LOW_BATTERY_ALARM_CLEAR_REGISTER, "--set-low-battery-alarm-clear")
        elif args.set_ac_frequency is not None:
            action_desc = f"set its AC output frequency to {args.set_ac_frequency} Hz"
            command_hex = build_register_write(AC_FREQUENCY_REGISTER, AC_FREQUENCY_VALUES[args.set_ac_frequency], 1)
        elif args.set_dynamic_cutoff is not None:
            action_desc = f"set its Dynamic cutoff voltage enabled to '{args.set_dynamic_cutoff.upper()}'"
            command_hex = build_register_write(DYNAMIC_CUTOFF_REGISTER, DYNAMIC_CUTOFF_VALUES[args.set_dynamic_cutoff], 1)
        elif args.set_battery_capacity is not None:
            require_range(args.set_battery_capacity, 0, 0xFFFF, "--set-battery-capacity")
            action_desc = f"set its battery capacity to {args.set_battery_capacity} Ah"
            command_hex = build_register_write(BATTERY_CAPACITY_REGISTER, args.set_battery_capacity, 2)
        else:
            def dyn_cutoff_command(volts, register, name):
                require_range(volts, DYN_CUTOFF_FACTOR_MIN, DYN_CUTOFF_FACTOR_MAX, name)
                raw = round(volts * 1000)
                return build_register_write(register, raw, 2)

            if args.set_dyn_cutoff_0005 is not None:
                action_desc = f"set its dynamic cutoff factor at 0.005A to {args.set_dyn_cutoff_0005} V"
                command_hex = dyn_cutoff_command(args.set_dyn_cutoff_0005, DYN_CUTOFF_FACTOR_0005_REGISTER, "--set-dyn-cutoff-0005")
            elif args.set_dyn_cutoff_0250 is not None:
                action_desc = f"set its dynamic cutoff factor at 0.250A to {args.set_dyn_cutoff_0250} V"
                command_hex = dyn_cutoff_command(args.set_dyn_cutoff_0250, DYN_CUTOFF_FACTOR_0250_REGISTER, "--set-dyn-cutoff-0250")
            elif args.set_dyn_cutoff_0700 is not None:
                action_desc = f"set its dynamic cutoff factor at 0.700A to {args.set_dyn_cutoff_0700} V"
                command_hex = dyn_cutoff_command(args.set_dyn_cutoff_0700, DYN_CUTOFF_FACTOR_0700_REGISTER, "--set-dyn-cutoff-0700")
            elif args.set_dyn_cutoff_2000 is not None:
                action_desc = f"set its dynamic cutoff factor at 2.000A to {args.set_dyn_cutoff_2000} V"
                command_hex = dyn_cutoff_command(args.set_dyn_cutoff_2000, DYN_CUTOFF_FACTOR_2000_REGISTER, "--set-dyn-cutoff-2000")
            elif args.set_lock_code is not None:
                if not re.fullmatch(r"\d{8}", args.set_lock_code):
                    sys.exit("--set-lock-code must be exactly 8 digits")
                code = int(args.set_lock_code)
                timestamp = int(time.time())
                action_desc = f"set its settings lock code to {args.set_lock_code}"
                command_hex = [
                    build_register_write(LOCK_CODE_TIMESTAMPED_REGISTER, code | (timestamp << 32), 8),
                    build_register_write(LOCK_CODE_REGISTER, code, 4),
                ]
            elif args.unlock_settings:
                timestamp = int(time.time())
                action_desc = "remove its settings lock code"
                command_hex = build_register_write(
                    LOCK_CODE_TIMESTAMPED_REGISTER, UNLOCK_SENTINEL | (timestamp << 32), 8
                )
            else:
                # Battery "type" isn't its own register -- VictronConnect just
                # bundles fixed dynamic-cutoff-curve values per preset and
                # shows "Custom" whenever the curve doesn't match a preset.
                # This sends all four registers for the chosen preset, one
                # per (re)connection -- see BATTERY_TYPE_PRESETS and the note
                # on multi-write connections in main().
                preset = BATTERY_TYPE_PRESETS[args.set_battery_type]
                action_desc = f"set its battery type to '{args.set_battery_type}' (dynamic cutoff curve preset)"
                command_hex = [build_register_write(register, round(volts * 1000), 2) for register, volts in preset]

    print(f"About to connect to {mac} and {action_desc}.")
    print("This sends an unofficial, reverse-engineered command directly to your")
    print("inverter's control characteristic over Bluetooth. It could put the")
    print("device into an unexpected state if the inverter firmware differs from")
    print("the one this was reverse-engineered against.")
    if not args.yes:
        answer = input("Type 'yes' to proceed: ").strip().lower()
        if answer != "yes":
            print("Aborted.")
            return

    commands = command_hex if isinstance(command_hex, list) else [command_hex]
    if len(commands) == 1:
        send_commands(args, mac, addr_type, pin, commands)
    else:
        # A batch of register writes sent within one connection was observed
        # reliably disconnecting the inverter partway through (after exactly
        # 3 successful writes, regardless of what -- if anything -- was sent
        # between them). Reconnecting fresh for each write is slower but
        # matches what's actually been verified to work reliably.
        for i, hex_data in enumerate(commands):
            print(f"--- write {i + 1}/{len(commands)} ---")
            send_commands(args, mac, addr_type, pin, [hex_data])
    print("Done.")


def send_commands(args, mac: str, addr_type: int, pin: str, commands: list):
    """Connect, pair, and send the given list of already-built command hex
    strings to the command characteristic within a single connection."""
    client = BleuIOGattClient(port=args.port, baud=args.baud, verbose=args.verbose)
    print(f"Connected to BleuIO dongle on {client.port_name}")

    try:
        if not client.connect(mac, addr_type):
            sys.exit(f"Could not connect to {mac}. Is it powered and in range?")
        print(f"Connected to {mac}, pairing...")

        if not client.pair(pin):
            sys.exit("Pairing failed -- check the PIN.")
        print("Paired and bonded.")

        handles = client.discover_handles()
        control_handle = handles.get(CONTROL_CHAR_UUID)
        command_handle = handles.get(COMMAND_CHAR_UUID)
        if not control_handle or not command_handle:
            sys.exit(
                "Could not find the expected control/command characteristics on "
                f"this device (found handles: {handles}). This inverter's "
                "firmware may use a different GATT layout than the one this "
                "script was reverse-engineered against -- stopping rather than "
                "guessing."
            )
        print(f"Found control characteristic at handle {control_handle}, "
              f"command characteristic at handle {command_handle}.")

        uuid_to_handle = {CONTROL_CHAR_UUID: control_handle, COMMAND_CHAR_UUID: command_handle}
        print("Sending init sequence...")
        for uuid, hex_data in INIT_SEQUENCE:
            client.write_handle(uuid_to_handle[uuid], hex_data)

        for hex_data in commands:
            client.write_handle(command_handle, hex_data)
        time.sleep(0.5)
    finally:
        client.disconnect()
        client.close()


if __name__ == "__main__":
    main()
