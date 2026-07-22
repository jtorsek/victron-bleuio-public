#!/usr/bin/env python3
"""
Scan for Victron Energy BLE "Instant Readout" devices using a BleuIO Pro
USB BLE dongle, list what's found, and decode the broadcasted values.

How it works
------------
The BleuIO Pro is driven over a virtual serial port with plain AT commands.
This script:

  1. Auto-detects the BleuIO Pro's serial port (falls back to any BleuIO
     dongle) via its USB VID:PID, or uses --port if given.
  2. Puts the dongle in dual/central role and runs `AT+GAPSCAN` to find
     nearby BLE devices.
  3. For each device found, runs `AT+SCANTARGET` to grab its raw
     advertisement payload and looks for a Manufacturer Specific Data
     structure (AD type 0xFF) whose company ID is 0x02E1 (Victron Energy)
     and whose payload starts with 0x10 (the Instant Readout marker).
  4. Any device matching that is listed as a Victron device, with its
     model name resolved from Victron's model ID table.
  5. If you supply the device's per-device "advertisement key" (see below),
     the encrypted payload is decrypted (AES-128-CTR) and decoded into
     real values (voltage, current, SoC, solar yield, etc.) for the
     device types this script knows how to parse: Battery Monitors
     (BMV / SmartShunt) and Solar Chargers (BlueSolar / SmartSolar MPPT).
     Other Victron BLE device types are listed but not decoded.

Getting the advertisement key
------------------------------
Victron encrypts the Instant Readout payload per-device. To decrypt a
device's broadcasts you need its key, which you fetch once from the
official VictronConnect app: connect to the device, open
Settings -> Product info -> Instant readout via Bluetooth, and tap
"Show" next to the advertisement key. It's a 32-character hex string.

Put the keys you want to decode in a small JSON file, keyed by MAC
address (case-insensitive), e.g. keys.json:

    {
      "C1:22:33:44:55:66": "aabbccddeeff00112233445566778899",
      "D2:33:44:55:66:77": "00112233445566778899aabbccddeeff"
    }

Then run:

    python3 victron_bleuio_scanner.py --keys-file keys.json

Devices you have no key for are still listed (address, RSSI, name,
model), just not decrypted.

Requirements
------------
    pip install pyserial pycryptodome

Usage
-----
    python3 victron_bleuio_scanner.py [--port /dev/tty.usbmodemXXXX]
                                       [--baud 115200]
                                       [--scan-time 10]
                                       [--target-scan-time 4]
                                       [--keys-file keys.json]
                                       [--watch] [--interval 10]
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional, Tuple

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    sys.exit("Missing dependency 'pyserial'. Install it with: pip install pyserial")

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    from Crypto.Util.Padding import pad
except ImportError:
    sys.exit(
        "Missing dependency 'pycryptodome'. Install it with: pip install pycryptodome"
    )


# --------------------------------------------------------------------------
# BleuIO Pro dongle interface (plain AT commands over a virtual serial port)
# --------------------------------------------------------------------------

# USB VID:PID for the BleuIO family (Smart Sensor Devices AB).
# 2DCF:6001 = BleuIO, 2DCF:6002 = BleuIO Pro.
BLEUIO_HWID_MARKERS = ("VID:PID=2DCF:6001", "VID:PID=2DCF:6002")

DEVICE_LINE_RE = re.compile(
    r"\[\d+\]\s*Device:\s*\[(?P<addr_type>\d)\](?P<mac>[0-9A-F:]{17})"
    r"\s+RSSI:\s*(?P<rssi>-?\d+)(?:\s+\((?P<name>.+?)\))?"
)


def find_dongle_port() -> Optional[str]:
    """Auto-detect a connected BleuIO / BleuIO Pro dongle's serial port."""
    for port in list_ports.comports():
        hwid = port.hwid or ""
        if any(marker in hwid for marker in BLEUIO_HWID_MARKERS):
            return port.device
    return None


class BleuIODongle:
    def __init__(self, port: Optional[str], baud: int, verbose: bool = False):
        self.port_name = port or find_dongle_port()
        if not self.port_name:
            sys.exit(
                "No BleuIO dongle found on any USB serial port. "
                "Plug it in, or pass --port explicitly (see `ls /dev/tty.*`)."
            )
        self.verbose = verbose
        try:
            self.ser = serial.Serial(self.port_name, baud, timeout=1)
        except serial.SerialException as e:
            sys.exit(f"Could not open {self.port_name}: {e}")
        time.sleep(0.3)
        self.ser.reset_input_buffer()
        self._send("AT+DUAL")  # dual/central role, required before scanning
        time.sleep(0.2)
        self.ser.reset_input_buffer()

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def _send(self, cmd: str):
        if self.verbose:
            print(f">> {cmd}")
        self.ser.write((cmd + "\r\n").encode())

    def _read_lines(self, duration: float):
        deadline = time.time() + duration
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

    def scan(self, duration: int) -> Dict[str, dict]:
        """Run a general GAP scan and return {mac: {addr_type, rssi, name}}."""
        self.ser.reset_input_buffer()
        self._send(f"AT+GAPSCAN={duration}")
        lines = self._read_lines(duration + 1.5)

        devices: Dict[str, dict] = {}
        for line in lines:
            m = DEVICE_LINE_RE.search(line)
            if m:
                mac = m.group("mac").upper()
                devices[mac] = {
                    "addr_type": int(m.group("addr_type")),
                    "rssi": int(m.group("rssi")),
                    "name": (m.group("name") or "").strip(),
                }
        return devices

    def read_raw_adv(self, mac: str, addr_type: int, duration: int) -> Optional[str]:
        """Target-scan a single device and return its raw advertisement hex."""
        self.ser.reset_input_buffer()
        self._send(f"AT+SCANTARGET=[{addr_type}]{mac}={duration}")
        lines = self._read_lines(duration + 1.5)
        for line in lines:
            if "Device Data [ADV]:" in line:
                return line.split("Device Data [ADV]:", 1)[1].strip()
        return None


# --------------------------------------------------------------------------
# BLE advertisement (AD structure) parsing
# --------------------------------------------------------------------------

VICTRON_MANUFACTURER_ID = 0x02E1


def parse_ad_structures(hex_str: str):
    data = bytes.fromhex(hex_str)
    i = 0
    out = []
    while i < len(data):
        length = data[i]
        if length == 0 or i + length >= len(data):
            break
        ad_type = data[i + 1]
        ad_data = data[i + 2 : i + 1 + length]
        out.append((ad_type, ad_data))
        i += length + 1
    return out


def extract_victron_payload(hex_str: str) -> Optional[bytes]:
    """Pull out Victron's Instant Readout manufacturer-data payload, if present."""
    for ad_type, ad_data in parse_ad_structures(hex_str):
        if ad_type == 0xFF and len(ad_data) >= 2:
            company_id = ad_data[0] | (ad_data[1] << 8)
            if company_id == VICTRON_MANUFACTURER_ID:
                payload = ad_data[2:]
                if payload[:1] == b"\x10":
                    return payload
    return None


# --------------------------------------------------------------------------
# Victron Instant Readout protocol: container + AES-CTR decryption
#
# Payload layout (all little-endian):
#   byte 0-1   prefix (0x10, plus a padding byte)
#   byte 2-3   model id (uint16)
#   byte 4     readout/record type (which kind of device this is)
#   byte 5-6   IV / nonce counter (uint16)
#   byte 7     key-check byte (must equal first byte of the device's key)
#   byte 8-... AES-128-CTR encrypted payload
# --------------------------------------------------------------------------


@dataclass
class VictronContainer:
    model_id: int
    readout_type: int
    iv: int
    encrypted_data: bytes


class AdvertisementKeyMismatchError(Exception):
    pass


def parse_container(data: bytes) -> VictronContainer:
    return VictronContainer(
        model_id=struct.unpack("<H", data[2:4])[0],
        readout_type=struct.unpack("<B", data[4:5])[0],
        iv=struct.unpack("<H", data[5:7])[0],
        encrypted_data=data[7:],
    )


def decrypt_victron_payload(data: bytes, key_hex: str) -> bytes:
    container = parse_container(data)
    key = bytes.fromhex(key_hex)

    if container.encrypted_data[0] != key[0]:
        raise AdvertisementKeyMismatchError(
            "Advertisement key does not match this device (key-check byte mismatch)"
        )

    ctr = Counter.new(128, initial_value=container.iv, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(pad(container.encrypted_data[1:], 16))


# Reads bit-field structures from LSB to MSB, in the order Victron packs
# them in the decrypted Extra Manufacturer Data payload.
class BitReader:
    def __init__(self, data: bytes):
        self._data = data
        self._index = 0

    def read_bit(self) -> int:
        bit = (self._data[self._index >> 3] >> (self._index & 7)) & 1
        self._index += 1
        return bit

    def read_unsigned_int(self, num_bits: int) -> int:
        value = 0
        for position in range(num_bits):
            value |= self.read_bit() << position
        return value

    def read_signed_int(self, num_bits: int) -> int:
        return BitReader.to_signed_int(self.read_unsigned_int(num_bits), num_bits)

    @staticmethod
    def to_signed_int(value: int, num_bits: int) -> int:
        return value - (1 << num_bits) if value & (1 << (num_bits - 1)) else value


# --- Enums used by the decoded fields (source: VE.Direct protocol docs) ---


class OperationMode(Enum):
    OFF = 0
    LOW_POWER = 1
    FAULT = 2
    BULK = 3
    ABSORPTION = 4
    FLOAT = 5
    STORAGE = 6
    EQUALIZE_MANUAL = 7
    INVERTING = 9
    POWER_SUPPLY = 11
    STARTING_UP = 245
    REPEATED_ABSORPTION = 246
    RECONDITION = 247
    BATTERY_SAFE = 248
    ACTIVE = 249
    EXTERNAL_CONTROL = 252
    NOT_AVAILABLE = 255


class ChargerError(Enum):
    NO_ERROR = 0
    TEMPERATURE_BATTERY_HIGH = 1
    VOLTAGE_HIGH = 2
    REMOTE_TEMPERATURE_A = 3
    REMOTE_TEMPERATURE_B = 4
    REMOTE_TEMPERATURE_C = 5
    REMOTE_BATTERY_A = 6
    REMOTE_BATTERY_B = 7
    REMOTE_BATTERY_C = 8
    HIGH_RIPPLE = 11
    TEMPERATURE_BATTERY_LOW = 14
    TEMPERATURE_CHARGER = 17
    OVER_CURRENT = 18
    BULK_TIME = 20
    CURRENT_SENSOR = 21
    INTERNAL_TEMPERATURE_A = 22
    INTERNAL_TEMPERATURE_B = 23
    FAN = 24
    OVERHEATED = 26
    SHORT_CIRCUIT = 27
    CONVERTER_ISSUE = 28
    OVER_CHARGE = 29
    INPUT_VOLTAGE = 33
    INPUT_CURRENT = 34
    INPUT_POWER = 35
    INPUT_SHUTDOWN_VOLTAGE = 38
    INPUT_SHUTDOWN_CURRENT = 39
    INPUT_SHUTDOWN_FAILURE = 40
    INVERTER_SHUTDOWN_41 = 41
    INVERTER_SHUTDOWN_42 = 42
    INVERTER_SHUTDOWN_43 = 43
    INVERTER_OVERLOAD = 50
    INVERTER_TEMPERATURE = 51
    INVERTER_PEAK_CURRENT = 52
    INVERTER_OUPUT_VOLTAGE_A = 53
    INVERTER_OUPUT_VOLTAGE_B = 54
    INVERTER_SELF_TEST_A = 55
    INVERTER_SELF_TEST_B = 56
    INVERTER_AC = 57
    INVERTER_SELF_TEST_C = 58
    COMMUNICATION = 65
    SYNCHRONISATION = 66
    BMS = 67
    NETWORK_A = 68
    NETWORK_B = 69
    NETWORK_C = 70
    NETWORK_D = 71
    PV_INPUT_SHUTDOWN_80 = 80
    PV_INPUT_SHUTDOWN_81 = 81
    PV_INPUT_SHUTDOWN_82 = 82
    PV_INPUT_SHUTDOWN_83 = 83
    PV_INPUT_SHUTDOWN_84 = 84
    PV_INPUT_SHUTDOWN_85 = 85
    PV_INPUT_SHUTDOWN_86 = 86
    PV_INPUT_SHUTDOWN_87 = 87
    CPU_TEMPERATURE = 114
    CALIBRATION_LOST = 116
    FIRMWARE = 117
    SETTINGS = 119
    TESTER_FAIL = 121
    INTERNAL_DC_VOLTAGE_A = 200
    INTERNAL_DC_VOLTAGE_B = 201
    SELF_TEST = 202
    INTERNAL_SUPPLY_A = 203
    INTERNAL_SUPPLY_B = 205
    INTERNAL_SUPPLY_C = 212
    INTERNAL_SUPPLY_D = 215


class AlarmReason(Enum):
    NO_ALARM = 0
    LOW_VOLTAGE = 1
    HIGH_VOLTAGE = 2
    LOW_SOC = 4
    LOW_STARTER_VOLTAGE = 8
    HIGH_STARTER_VOLTAGE = 16
    LOW_TEMPERATURE = 32
    HIGH_TEMPERATURE = 64
    MID_VOLTAGE = 128
    OVERLOAD = 256
    DC_RIPPLE = 512
    LOW_V_AC_OUT = 1024
    HIGH_V_AC_OUT = 2048
    SHORT_CIRCUIT = 4096
    BMS_LOCKOUT = 8192


class AuxMode(Enum):
    STARTER_VOLTAGE = 0
    MIDPOINT_VOLTAGE = 1
    TEMPERATURE = 2
    DISABLED = 3


def kelvin_to_celsius(temp_kelvin: float) -> float:
    return round(temp_kelvin - 273.15, 2)


# --- Per-device-type decoders -------------------------------------------


def decode_battery_monitor(decrypted: bytes) -> Dict[str, object]:
    """BMV / SmartShunt battery monitors (readout type 0x02)."""
    reader = BitReader(decrypted)

    remaining_mins = reader.read_unsigned_int(16)
    voltage = reader.read_signed_int(16)
    alarm = reader.read_unsigned_int(16)
    aux = reader.read_unsigned_int(16)
    aux_mode = reader.read_unsigned_int(2)
    current = reader.read_signed_int(22)
    consumed_ah = reader.read_unsigned_int(20)
    soc = reader.read_unsigned_int(10)

    values: Dict[str, object] = {
        "remaining_mins": remaining_mins if remaining_mins != 0xFFFF else None,
        "voltage_v": voltage / 100 if voltage != 0x7FFF else None,
        "alarm": AlarmReason(alarm).name,
        "current_a": current / 1000 if current != 0x3FFFFF else None,
        "consumed_ah": -consumed_ah / 10 if consumed_ah != 0xFFFFF else None,
        "soc_percent": soc / 10 if soc != 0x3FF else None,
    }

    if aux_mode == AuxMode.STARTER_VOLTAGE.value:
        values["starter_voltage_v"] = BitReader.to_signed_int(aux, 16) / 100
    elif aux_mode == AuxMode.MIDPOINT_VOLTAGE.value:
        values["midpoint_voltage_v"] = aux / 100
    elif aux_mode == AuxMode.TEMPERATURE.value:
        values["temperature_c"] = kelvin_to_celsius(aux / 100)

    return values


def decode_solar_charger(decrypted: bytes) -> Dict[str, object]:
    """BlueSolar / SmartSolar MPPT charge controllers (readout type 0x01)."""
    reader = BitReader(decrypted)

    charge_state = reader.read_unsigned_int(8)
    charger_error = reader.read_unsigned_int(8)
    battery_voltage = reader.read_signed_int(16)
    battery_current = reader.read_signed_int(16)
    yield_today = reader.read_unsigned_int(16)
    solar_power = reader.read_unsigned_int(16)
    external_load = reader.read_unsigned_int(9)

    return {
        "charge_state": (
            OperationMode(charge_state).name if charge_state != 0xFF else None
        ),
        "charger_error": (
            ChargerError(charger_error).name if charger_error != 0xFF else None
        ),
        "battery_voltage_v": (
            battery_voltage / 100 if battery_voltage != 0x7FFF else None
        ),
        "battery_current_a": (
            battery_current / 10 if battery_current != 0x7FFF else None
        ),
        "yield_today_wh": yield_today * 10 if yield_today != 0xFFFF else None,
        "solar_power_w": solar_power if solar_power != 0xFFFF else None,
        "external_load_a": (
            external_load / 10 if external_load != 0x1FF else None
        ),
    }


def decode_inverter(decrypted: bytes) -> Dict[str, object]:
    """Phoenix Inverter / Phoenix Smart Inverter (readout type 0x03)."""
    reader = BitReader(decrypted)

    device_state = reader.read_unsigned_int(8)
    alarm = reader.read_unsigned_int(16)
    battery_voltage = reader.read_signed_int(16)
    ac_apparent_power = reader.read_unsigned_int(16)
    ac_voltage = reader.read_unsigned_int(15)
    ac_current = reader.read_unsigned_int(11)

    return {
        "device_state": (
            OperationMode(device_state).name if device_state != 0xFF else None
        ),
        "alarm": AlarmReason(alarm).name if alarm > 0 else "NO_ALARM",
        "battery_voltage_v": (
            battery_voltage / 100 if battery_voltage != 0x7FFF else None
        ),
        "ac_apparent_power_va": (
            ac_apparent_power if ac_apparent_power != 0xFFFF else None
        ),
        "ac_voltage_v": ac_voltage / 100 if ac_voltage != 0x7FFF else None,
        "ac_current_a": ac_current / 10 if ac_current != 0x7FF else None,
    }


# readout_type -> (human label, decoder function)
READOUT_TYPE_DECODERS: Dict[int, Tuple[str, Callable[[bytes], Dict[str, object]]]] = {
    0x1: ("Solar Charger", decode_solar_charger),
    0x2: ("Battery Monitor", decode_battery_monitor),
    0x3: ("Inverter", decode_inverter),
}

# readout_type -> human label, for types we recognize but don't decode yet
READOUT_TYPE_LABELS: Dict[int, str] = {
    0x1: "Solar Charger",
    0x2: "Battery Monitor",
    0x3: "Inverter",
    0x4: "DC-DC Converter",
    0x5: "Smart Lithium Battery",
    0x6: "Inverter RS",
    0x8: "AC Charger",
    0x9: "Smart BatteryProtect",
    0xA: "Lynx Smart BMS",
    0xB: "Multi RS",
    0xC: "VE.Bus",
    0xD: "DC Energy Meter",
    0xF: "Orion XS",
}


# --------------------------------------------------------------------------
# Victron model id -> product name (source: VE.Direct protocol docs)
# --------------------------------------------------------------------------

MODEL_ID_MAPPING = {
    0x203: "BMV-700",
    0x204: "BMV-702",
    0x205: "BMV-700H",
    0xA380: "BMV-710 Smart",
    0xA381: "BMV-712 Smart",
    0xA382: "BMV-710H Smart",
    0xA383: "BMV-712 Smart",
    0xC034: "BMV-800 Smart",
    0xA389: "SmartShunt 500A/50mV",
    0xA38A: "SmartShunt 1000A/50mV",
    0xA38B: "SmartShunt 2000A/50mV",
    0xA38C: "SmartShunt IP67 500A/50mV",
    0xA38D: "SmartShunt IP67 1000A/50mV",
    0xA38E: "SmartShunt IP67 2000A/50mV",
    0xC030: "SmartShunt IP65 500A/50mV",
    0xC031: "SmartShunt IP65 1000A/50mV",
    0xC032: "SmartShunt IP65 2000A/50mV",
    0xC035: "SmartShunt IP65 500A/50mV",
    0xC036: "SmartShunt IP65 1000A/50mV",
    0xC037: "SmartShunt IP65 2000A/50mV",
    0xC038: "SmartShunt 300A/50mV",
    0xA3A4: "Smart Battery Sense",
    0xA3A5: "Smart Battery Sense (Rev2)",
    0xA040: "BlueSolar Charger MPPT 75/50",
    0xA041: "BlueSolar Charger MPPT 150/35 rev1",
    0xA042: "BlueSolar Charger MPPT 75/15",
    0xA043: "BlueSolar Charger MPPT 100/15",
    0xA044: "BlueSolar Charger MPPT 100/30 rev1",
    0xA045: "BlueSolar Charger MPPT 100/50 rev1",
    0xA046: "BlueSolar Charger MPPT 150/70",
    0xA047: "BlueSolar Charger MPPT 150/100",
    0xA048: "BlueSolar Charger MPPT 75/50 rev2",
    0xA049: "BlueSolar Charger MPPT 100/50 rev2",
    0xA04A: "BlueSolar Charger MPPT 100/30 rev2",
    0xA04B: "BlueSolar Charger MPPT 150/35 rev2",
    0xA04C: "BlueSolar Charger MPPT 75/10",
    0xA04D: "BlueSolar Charger MPPT 150/45",
    0xA04E: "BlueSolar Charger MPPT 150/60",
    0xA04F: "BlueSolar Charger MPPT 150/85",
    0xA050: "SmartSolar Charger MPPT 250/100",
    0xA051: "SmartSolar Charger MPPT 150/100",
    0xA052: "SmartSolar Charger MPPT 150/85",
    0xA053: "SmartSolar Charger MPPT 75/15",
    0xA054: "SmartSolar Charger MPPT 75/10",
    0xA055: "SmartSolar Charger MPPT 100/15",
    0xA056: "SmartSolar Charger MPPT 100/30",
    0xA057: "SmartSolar Charger MPPT 100/50",
    0xA058: "SmartSolar Charger MPPT 150/35",
    0xA059: "SmartSolar Charger MPPT 150/100 rev2",
    0xA05A: "SmartSolar Charger MPPT 150/85 rev2",
    0xA05B: "SmartSolar Charger MPPT 250/70",
    0xA05C: "SmartSolar Charger MPPT 250/85",
    0xA05D: "SmartSolar Charger MPPT 250/60",
    0xA05E: "SmartSolar Charger MPPT 250/60",
    0xA05F: "SmartSolar Charger MPPT 100/20",
    0xA060: "SmartSolar Charger MPPT 100/20 48V",
    0xA061: "SmartSolar Charger MPPT 150/45",
    0xA062: "SmartSolar Charger MPPT 150/60",
    0xA063: "SmartSolar Charger MPPT 150/70",
    0xA064: "SmartSolar Charger MPPT 250/85 rev2",
    0xA065: "SmartSolar Charger MPPT 250/100 rev2",
    0xA066: "BlueSolar Charger MPPT 100/20",
    0xA067: "BlueSolar Charger MPPT 100/20 48V",
    0xA068: "SmartSolar Charger MPPT 250/60 rev2",
    0xA069: "SmartSolar Charger MPPT 250/70 rev2",
    0xA06A: "SmartSolar Charger MPPT 150/45 rev2",
    0xA06B: "SmartSolar Charger MPPT 150/60 rev2",
    0xA06C: "SmartSolar Charger MPPT 150/70 rev2",
    0xA06D: "SmartSolar Charger MPPT 150/85 rev3",
    0xA06E: "SmartSolar Charger MPPT 150/100 rev3",
    0xA06F: "BlueSolar Charger MPPT 150/45 rev2",
    0xA070: "BlueSolar Charger MPPT 150/60 rev2",
    0xA071: "BlueSolar Charger MPPT 150/70 rev2",
    0xA072: "BlueSolar Charger MPPT 150/45 rev3",
    0xA073: "SmartSolar Charger MPPT 150/45 rev3",
    0xA074: "SmartSolar Charger MPPT 75/10 rev2",
    0xA075: "SmartSolar Charger MPPT 75/15 rev2",
    0xA076: "BlueSolar Charger MPPT 100/30 rev3",
    0xA077: "BlueSolar Charger MPPT 100/50 rev3",
    0xA078: "BlueSolar Charger MPPT 150/35 rev3",
    0xA079: "BlueSolar Charger MPPT 75/10 rev2",
    0xA07A: "BlueSolar Charger MPPT 75/15 rev2",
    0xA07B: "BlueSolar Charger MPPT 100/15 rev2",
    0xA07C: "BlueSolar Charger MPPT 75/10 rev3",
    0xA07D: "BlueSolar Charger MPPT 75/15 rev3",
    0xA07E: "SmartSolar Charger MPPT 100/30 12V",
    0xA102: "SmartSolar MPPT VE.Can 150/70",
    0xA103: "SmartSolar MPPT VE.Can 150/45",
    0xA104: "SmartSolar MPPT VE.Can 150/60",
    0xA105: "SmartSolar MPPT VE.Can 150/85",
    0xA106: "SmartSolar MPPT VE.Can 150/100",
    0xA107: "SmartSolar MPPT VE.Can 250/45",
    0xA108: "SmartSolar MPPT VE.Can 250/60",
    0xA109: "SmartSolar MPPT VE.Can 250/70",
    0xA10A: "SmartSolar MPPT VE.Can 250/85",
    0xA10B: "SmartSolar MPPT VE.Can 250/100",
    0xA10C: "SmartSolar MPPT VE.Can 150/70 rev2",
    0xA10D: "SmartSolar MPPT VE.Can 150/85 rev2",
    0xA10E: "SmartSolar MPPT VE.Can 150/100 rev2",
    0xA10F: "BlueSolar MPPT VE.Can 150/100",
    0xA110: "SmartSolar MPPT RS 450/100",
    0xA111: "SmartSolar MPPT RS 450/200",
    0xA112: "BlueSolar MPPT VE.Can 250/70",
    0xA113: "BlueSolar MPPT VE.Can 250/100",
    0xA114: "SmartSolar MPPT VE.Can 250/70 rev2",
    0xA115: "SmartSolar MPPT VE.Can 250/100 rev2",
    0xA116: "SmartSolar MPPT VE.Can 250/85 rev2",
    0xA117: "BlueSolar MPPT VE.Can 150/100 rev2",
    0xA0C1: "Lithium Battery Balancer 12V/3.5A",
    0xA0C2: "Lithium Battery Balancer 12V/8A",
    0xA0C3: "Lithium Battery Balancer 24V/3.5A",
    0xA0C4: "Lithium Battery Balancer 12V/2A",
    0xA0E0: "Smart Lithium Battery 12.8V/90Ah",
    0xA0E1: "Smart Lithium Battery 12.8V/60Ah",
    0xA0E2: "Smart Lithium Battery 12.8V/160Ah",
    0xA0E3: "Smart Lithium Battery 12.8V/200Ah",
    0xA0E4: "Smart Lithium Battery 12.8V/300Ah",
    0xA0E5: "Smart Lithium Battery 12.8V/100Ah",
    0xA0E6: "Smart Lithium Battery 12.8V/200Ah",
    0xA0E7: "Smart Lithium Battery 12.8V/300Ah",
    0xA0E8: "Smart Lithium Battery 12.8V/100Ah",
    0xA0E9: "Smart Lithium Battery 12.8V/150Ah",
    0xA0EA: "Smart Lithium Battery 25.6V/200Ah",
    0xA0EB: "Smart Lithium Battery 12.8V/200Ah",
    0xA0EC: "Smart Lithium Battery 12.8V/160Ah",
    0xA0ED: "Smart Lithium Battery 12.8V/50Ah",
    0xA0EE: "Smart Lithium Battery 25.6V/200Ah",
    0xA0EF: "Smart Lithium Battery 25.6V/100Ah",
    0xA0F0: "Smart Lithium Battery 12.8V/330Ah",
    0xA0F1: "Smart Lithium Battery 25.6V/330Ah",
    0xA0F2: "Smart Lithium Battery 12.8V/300Ah",
    0xA130: "Lynx Ion + Shunt",
    0xA131: "Lynx Smart Shunt 1000A VE.Can",
    0xA390: "Lynx Ion BMS General",
    0xA391: "Lynx Ion BMS 150A",
    0xA392: "Lynx Ion BMS 400A",
    0xA393: "Lynx Ion BMS 600A",
    0xA394: "Lynx Ion BMS 1000A",
    0xA3E5: "Lynx Smart BMS 500",
    0xA3E6: "Lynx Smart BMS 1000",
    0xA3B0: "Smart BatteryProtect 12/24V-65A",
    0xA3B1: "Smart BatteryProtect 12/24V-100A",
    0xA3B2: "Smart BatteryProtect 12/24V-220A",
    0xA3B3: "Smart BatteryProtect 48V-100A",
    0xA3C0: "Orion Smart 12V/12V-18A DC-DC Converter",
    0xA3C1: "Orion Smart 12V/24V-10A DC-DC Converter",
    0xA3C2: "Orion Smart 24V/12V-20A DC-DC Converter",
    0xA3C3: "Orion Smart 24V/24V-12A DC-DC Converter",
    0xA3C4: "Orion Smart 24V/48V-6A DC-DC Converter",
    0xA3C5: "Orion Smart 48V/12V-20A DC-DC Converter",
    0xA3C6: "Orion Smart 48V/24V-12A DC-DC Converter",
    0xA3C7: "Orion Smart 48V/48V-6A DC-DC Converter",
    0xA3C8: "Orion Smart 12V/12V-30A DC-DC Converter",
    0xA3C9: "Orion Smart 12V/24V-15A DC-DC Converter",
    0xA3CA: "Orion Smart 24V/12V-30A DC-DC Converter",
    0xA3CB: "Orion Smart 24V/24V-17A DC-DC Converter",
    0xA3CC: "Orion Smart 24V/48V-8.5A DC-DC Converter",
    0xA3CD: "Orion Smart 48V/12V-30A DC-DC Converter",
    0xA3CE: "Orion Smart 48V/24V-16A DC-DC Converter",
    0xA3CF: "Orion Smart 48V/48V-8A DC-DC Converter",
    0xA3D0: "Orion Smart 12V/12V-30A Buck-Boost Converter",
    0xA3D1: "Orion Smart 12V/24V-15A Buck-Boost Converter",
    0xA3D2: "Orion Smart Orion 24V/12V-30A Buck-Boost Converter",
    0xA3D3: "Orion Smart Orion 24V/24V-17A Buck-Boost Converter",
    0xA3E0: "Smart BMS CL 12-100",
    0xA3E8: "Smart BMS 12-200",
    0xA3EC: "smallBMS",
    0xA3F0: "Smart Buckboost 12V/12V-50A non-iso DC-DC charger",
    0xA401: "Inverter RS Solar 48V/6000VA/80A",
    0xA402: "Inverter RS 48V/6000VA",
    0xA441: "Multi RS Solar 48V/6000VA/100A",
    0xA442: "Multi RS Solar 48V/6000VA/100A",
    0xA443: "Multi RS Solar 48V/6000VA/100A",
    0xA444: "Multi RS Solar 48V/6000VA/100A",
    0xA300: "Blue Smart Charger - Generic",
    0xA301: "Blue Smart IP65 Charger 12|10",
    0xA302: "Blue Smart IP65 Charger 12|15",
    0xA303: "Blue Smart IP65 Charger 24|8",
    0xA304: "Blue Smart IP65 Charger 12|5",
    0xA305: "Blue Smart IP65 Charger 12|7",
    0xA306: "Blue Smart IP65 Charger 24|5",
    0xA307: "Blue Smart IP65 Charger 12|4",
    0xA310: "Blue Smart IP67 Charger 12|7",
    0xA311: "Blue Smart IP67 Charger 12|13",
    0xA312: "Blue Smart IP67 Charger 24|5",
    0xA313: "Blue Smart IP67 Charger 12|17",
    0xA314: "Blue Smart IP67 Charger 12|25",
    0xA315: "Blue Smart IP67 Charger 24|8",
    0xA316: "Blue Smart IP67 Charger 24|12",
    0xA320: "Blue Smart IP22 Charger 12|15 (1)",
    0xA321: "Blue Smart IP22 Charger 12|15 (3)",
    0xA322: "Blue Smart IP22 Charger 12|20 (1)",
    0xA323: "Blue Smart IP22 Charger 12|20 (3)",
    0xA324: "Blue Smart IP22 Charger 12|30 (1)",
    0xA325: "Blue Smart IP22 Charger 12|30 (3)",
    0xA326: "Blue Smart IP22 Charger 24|8 (1)",
    0xA327: "Blue Smart IP22 Charger 24|8 (3)",
    0xA328: "Blue Smart IP22 Charger 24|12 (1)",
    0xA329: "Blue Smart IP22 Charger 24|12 (3)",
    0xA200: "Phoenix Inverter",
    0xA201: "Phoenix Inverter 12V 250VA 230V",
    0xA202: "Phoenix Inverter 24V 250VA 230V",
    0xA204: "Phoenix Inverter 48V 250VA 230V",
    0xA211: "Phoenix Inverter 12V 375VA 230V",
    0xA212: "Phoenix Inverter 24V 375VA 230V",
    0xA214: "Phoenix Inverter 48V 375VA 230V",
    0xA221: "Phoenix Inverter 12V 500VA 230V",
    0xA222: "Phoenix Inverter 24V 500VA 230V",
    0xA224: "Phoenix Inverter 48V 500VA 230V",
    0xA231: "Phoenix Inverter 12V 250VA 230V",
    0xA232: "Phoenix Inverter 24V 250VA 230V",
    0xA234: "Phoenix Inverter 48V 250VA 230V",
    0xA239: "Phoenix Inverter 12V 250VA 120V",
    0xA23A: "Phoenix Inverter 24V 250VA 120V",
    0xA23C: "Phoenix Inverter 48V 250VA 120V",
    0xA241: "Phoenix Inverter 12V 375VA 230V",
    0xA242: "Phoenix Inverter 24V 375VA 230V",
    0xA244: "Phoenix Inverter 48V 375VA 230V",
    0xA249: "Phoenix Inverter 12V 375VA 120V",
    0xA24A: "Phoenix Inverter 24V 375VA 120V",
    0xA24C: "Phoenix Inverter 48V 375VA 120V",
    0xA251: "Phoenix Inverter 12V 500VA 230V",
    0xA252: "Phoenix Inverter 24V 500VA 230V",
    0xA254: "Phoenix Inverter 48V 500VA 230V",
    0xA259: "Phoenix Inverter 12V 500VA 120V",
    0xA25A: "Phoenix Inverter 24V 500VA 120V",
    0xA25C: "Phoenix Inverter 48V 500VA 120V",
    0xA261: "Phoenix Inverter 12V 800VA 230V",
    0xA262: "Phoenix Inverter 24V 800VA 230V",
    0xA264: "Phoenix Inverter 48V 800VA 230V",
    0xA269: "Phoenix Inverter 12V 800VA 120V",
    0xA26A: "Phoenix Inverter 24V 800VA 120V",
    0xA26C: "Phoenix Inverter 48V 800VA 120V",
    0xA271: "Phoenix Inverter 12V 1200VA 230V",
    0xA272: "Phoenix Inverter 24V 1200VA 230V",
    0xA274: "Phoenix Inverter 48V 1200VA 230V",
    0xA279: "Phoenix Inverter 12V 1200VA 120V",
    0xA27A: "Phoenix Inverter 24V 1200VA 120V",
    0xA27C: "Phoenix Inverter 48V 1200VA 120V",
    0xA281: "Smart Phoenix Inverter 12V 2000VA 230V",
    0xA282: "Smart Phoenix Inverter 24V 2000VA 230V",
    0xA284: "Smart Phoenix Inverter 48V 2000VA 230V",
    0xA289: "Smart Phoenix Inverter 12V 2000VA 120V",
    0xA28A: "Smart Phoenix Inverter 24V 2000VA 120V",
    0xA28C: "Smart Phoenix Inverter 48V 2000VA 120V",
    0xA291: "Smart Phoenix Inverter 12V 2000VA 230V",
    0xA292: "Smart Phoenix Inverter 24V 2000VA 230V",
    0xA294: "Smart Phoenix Inverter 48V 2000VA 230V",
    0xA299: "Smart Phoenix Inverter 12V 2000VA 120V",
    0xA29A: "Smart Phoenix Inverter 24V 2000VA 120V",
    0xA29C: "Smart Phoenix Inverter 48V 2000VA 120V",
    0xA2A1: "Smart Phoenix Inverter 12V 3000VA 230V",
    0xA2A2: "Smart Phoenix Inverter 24V 3000VA 230V",
    0xA2A4: "Smart Phoenix Inverter 48V 3000VA 230V",
    0xA2A9: "Smart Phoenix Inverter 12V 3000VA 120V",
    0xA2AA: "Smart Phoenix Inverter 24V 3000VA 120V",
    0xA2AC: "Smart Phoenix Inverter 48V 3000VA 120V",
    0xA2B2: "Smart Phoenix Inverter 24V 5000VA 230V",
    0xA2B4: "Smart Phoenix Inverter 48V 5000VA 230V",
    0xA2BA: "Smart Phoenix Inverter 24V 5000VA 120V",
    0xA2BC: "Smart Phoenix Inverter 48V 5000VA 120V",
    0xA2E1: "Phoenix Inverter 12V 800VA 230V",
    0xA2E2: "Phoenix Inverter 24V 800VA 230V",
    0xA2E4: "Phoenix Inverter 48V 800VA 230V",
    0xA2E9: "Phoenix Inverter 12V 800VA 120V",
    0xA2EA: "Phoenix Inverter 24V 800VA 120V",
    0xA2EC: "Phoenix Inverter 48V 800VA 120V",
    0xA2F1: "Phoenix Inverter 12V 1200VA 230V",
    0xA2F2: "Phoenix Inverter 24V 1200VA 230V",
    0xA2F4: "Phoenix Inverter 48V 1200VA 230V",
    0xA2F9: "Phoenix Inverter 12V 1200VA 120V",
    0xA2FA: "Phoenix Inverter 24V 1200VA 120V",
    0xA2FC: "Phoenix Inverter 48V 1200VA 120V",
    0xA340: "Phoenix Smart IP43 Charger 12|50 (1+1) 230V",
    0xA341: "Phoenix Smart IP43 Charger 12|50 (3) 230V",
    0xA342: "Phoenix Smart IP43 Charger 24|25 (1+1) 230V",
    0xA343: "Phoenix Smart IP43 Charger 24|25 (3) 230V",
    0xA344: "Phoenix Smart IP43 Charger 12|30 (1+1) 230V",
    0xA345: "Phoenix Smart IP43 Charger 12|30 (3) 230V",
    0xA346: "Phoenix Smart IP43 Charger 24|16 (1+1) 230V",
    0xA347: "Phoenix Smart IP43 Charger 24|16 (3) 230V",
    0xA182: "VE.Direct Bluetooth Smart Dongle",
    0xA188: "VE.Direct Bluetooth Smart Dongle (Rev2)",
    0xA189: "VE.Direct Bluetooth Smart Dongle (Rev3)",
    0xA190: "SmartSolar Bluetooth Interface",
    0xA191: "SmartSolar Bluetooth Interface (Rev2)",
    0xA192: "BMV-7xx Smart Bluetooth Interface",
    0xA193: "Lynx Ion BMS Bluetooth Interface",
    0xA194: "Phoenix Inverter Smart Bluetooth Interface",
    0xA195: "VE.Can SmartSolar Bluetooth Interface",
    0xA196: "SmartShunt Bluetooth Interface",
    0xA197: "SmartSolar Bluetooth Interface (Rev3)",
    0xA198: "BMV-7xx Smart Bluetooth Interface (Rev2)",
    0xA199: "Lynx Ion BMS Bluetooth Interface (Rev2)",
    0xA19A: "Phoenix Inverter Smart Bluetooth Interface (Rev2)",
    0xA19B: "VE.Can SmartSolar Bluetooth Interface (Rev2)",
    0xA19C: "SmartShunt Bluetooth Interface (Rev2)",
    0xA19D: "SmartShunt Bluetooth Interface (Rev2)",
    0xA19E: "Sun Inverter Bluetooth Interface",
    0xA19F: "All-In-1 Bluetooth Interface",
    0xC033: "All-In-1 Smart",
}


def model_name(model_id: int) -> str:
    return MODEL_ID_MAPPING.get(model_id, f"Unknown Victron model 0x{model_id:04X}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def load_keys(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    import json

    with open(path) as f:
        raw = json.load(f)
    return {mac.upper(): key.strip() for mac, key in raw.items()}


def run_once(dongle: BleuIODongle, keys: Dict[str, str], args) -> int:
    print(f"Scanning for BLE devices for {args.scan_time}s...")
    devices = dongle.scan(args.scan_time)
    print(f"Found {len(devices)} BLE device(s), checking each for Victron beacons...")

    victron = {}
    for mac, info in devices.items():
        raw_hex = dongle.read_raw_adv(mac, info["addr_type"], args.target_scan_time)
        if not raw_hex:
            continue
        payload = extract_victron_payload(raw_hex)
        if payload:
            victron[mac] = {**info, "payload": payload}

    if not victron:
        print("No Victron devices found.")
        return 0

    print(f"\nFound {len(victron)} Victron device(s):\n")
    for mac, info in sorted(victron.items()):
        model_id = struct.unpack("<H", info["payload"][2:4])[0]
        readout_type = info["payload"][4]
        label = READOUT_TYPE_LABELS.get(readout_type, f"Unknown type 0x{readout_type:02X}")
        name = info["name"] or "(no advertised name)"

        print(f"{mac}  RSSI {info['rssi']:>4} dBm  {name}")
        print(f"  Model: {model_name(model_id)}  [{label}]")

        key = keys.get(mac)
        if not key:
            print("  No advertisement key configured for this device — add it to")
            print("  your --keys-file to decode values. Raw payload:")
            print(f"    {info['payload'].hex()}")
            print()
            continue

        try:
            decrypted = decrypt_victron_payload(info["payload"], key)
        except AdvertisementKeyMismatchError as e:
            print(f"  Decrypt failed: {e}")
            print()
            continue
        except Exception as e:
            print(f"  Decrypt error: {e}")
            print()
            continue

        decoder_entry = READOUT_TYPE_DECODERS.get(readout_type)
        if not decoder_entry:
            print(f"  Decryption OK, but no field decoder implemented for '{label}' yet.")
            print(f"    Decrypted bytes: {decrypted.hex()}")
            print()
            continue

        _, decode_fn = decoder_entry
        values = decode_fn(decrypted)
        for k, v in values.items():
            print(f"    {k}: {v}")
        print()

    return len(victron)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan for and decode Victron Energy BLE Instant Readout devices "
            "using a BleuIO Pro USB BLE dongle."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--port", help="Serial port of the BleuIO dongle (default: auto-detect)")
    parser.add_argument("--baud", type=int, default=115200, help="Serial baud rate (default: 115200)")
    parser.add_argument("--scan-time", type=int, default=10, help="Seconds to run the general BLE scan (default: 10)")
    parser.add_argument("--target-scan-time", type=int, default=4, help="Seconds to target-scan each device for its raw advertisement (default: 4)")
    parser.add_argument("--keys-file", help="JSON file mapping MAC address -> Victron advertisement key")
    parser.add_argument("--watch", action="store_true", help="Repeat the scan/decode cycle continuously until Ctrl+C")
    parser.add_argument("--interval", type=int, default=15, help="Seconds to wait between cycles in --watch mode (default: 15)")
    parser.add_argument("--verbose", action="store_true", help="Print raw AT command traffic to/from the dongle")
    args = parser.parse_args()

    keys = load_keys(args.keys_file)

    dongle = BleuIODongle(port=args.port, baud=args.baud, verbose=args.verbose)
    print(f"Connected to BleuIO dongle on {dongle.port_name}\n")

    try:
        while True:
            run_once(dongle, keys, args)
            if not args.watch:
                break
            print(f"--- waiting {args.interval}s ---\n")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        dongle.close()


if __name__ == "__main__":
    main()
