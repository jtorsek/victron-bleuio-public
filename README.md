# Victron BLE Instant Readout & Inverter Control

Scans, decrypts, and decodes Victron Energy's BLE "Instant Readout" broadcasts
from a Victron Phoenix Inverter, and remotely controls its settings over BLE
GATT. Two independent implementations:

- **Python scripts** (`*.py`) -- run on a Mac/PC using a
  [BleuIO](https://www.bleu.io/) Pro USB BLE dongle.
- **LilyGo T-Display S3 firmware** (`lilygo_victron_display/`) -- runs
  standalone on the ESP32-S3 board itself, no computer needed after flashing.

## Python scripts

| File | What it does |
|---|---|
| `victron_bleuio_scanner.py` | Scans all nearby BLE devices, lists any Victron ones found, decodes their live values |
| `victron_bleuio_known_devices.py` | Same, but only looks for MAC addresses listed in `keys.json` |
| `victron_inverter_power_control.py` | Remotely changes the inverter's settings (power mode, AC voltage/frequency, eco mode, battery thresholds, battery capacity, dynamic cutoff) over BLE GATT |

### Setup

```bash
pip install -r requirements.txt
cp keys.json.example keys.json
cp inverter.json.example inverter.json
```

`keys.json` maps a device's MAC address to its Victron Instant Readout
advertisement key (from VictronConnect: Settings -> Product info -> Instant
readout via Bluetooth -> Show):

```json
{ "aa:bb:cc:dd:ee:ff": "00112233445566778899aabbccddeeff" }
```

`inverter.json` holds the MAC address, BLE address type, and Bluetooth
pairing PIN used by `victron_inverter_power_control.py`:

```json
{ "mac": "AA:BB:CC:DD:EE:FF", "addr_type": 1, "pin": "123456" }
```

Both are gitignored -- fill in your own device's values, never commit the
real files.

### Usage

```bash
python3 victron_bleuio_scanner.py --keys-file keys.json
python3 victron_bleuio_known_devices.py --keys-file keys.json
python3 victron_inverter_power_control.py --config inverter.json --set on
```

Run any script with `--help` for the full list of options (each settings
register `victron_inverter_power_control.py` supports, valid ranges, etc.).

## LilyGo T-Display S3 firmware

Standalone PlatformIO project (`lilygo_victron_display/`) for the LilyGo
T-Display S3. Once flashed, the board:

- Scans for the inverter's Instant Readout broadcast, decrypts it, and shows
  battery voltage / AC voltage / AC current / AC power on its built-in
  screen -- no phone, computer, or dongle needed.
- Has a touch button that connects to the inverter as a BLE client, pairs
  using the stored PIN, and toggles its power mode on/off.

Build and flash:

```bash
cd lilygo_victron_display
pio run --target upload
```

The inverter's MAC address, advertisement key, and pairing PIN are set as
constants near the top of `src/main.cpp`.

## Protocol notes

Victron's Instant Readout broadcast format (manufacturer ID `0x02E1`,
AES-128-CTR encrypted, bit-packed fields) is documented by Victron and has
prior open-source implementations (notably
[keshavdv/victron-ble](https://github.com/keshavdv/victron-ble)), which the
decoder here is ported from and was verified against.

The BLE GATT control protocol used to change inverter settings is
**unofficial and unsupported by Victron**. The power-mode write command
was sourced from a third-party reverse-engineering project
([Olen/VictronConnect](https://github.com/Olen/VictronConnect)); every other
settings register (Eco mode, AC voltage/frequency, battery thresholds,
battery capacity, dynamic cutoff) was reverse-engineered in this repo by
capturing real VictronConnect <-> inverter traffic with a Nordic nRF Sniffer
for Bluetooth LE and Wireshark, then confirmed by matching the decoded
values against the inverter's actual behavior. Use `victron_inverter_power_control.py`
and the firmware's write path on your own equipment, at your own risk.

## Requirements

- A [BleuIO](https://www.bleu.io/) or BleuIO Pro USB BLE dongle (for the
  Python scripts)
- Python 3 with `pyserial` and `pycryptodome`
- For the firmware: [PlatformIO](https://platformio.org/), a LilyGo
  T-Display S3, and a Nordic nRF52840 dongle running the nRF Sniffer for
  Bluetooth LE firmware (only needed if you want to reverse-engineer
  additional settings registers yourself)
