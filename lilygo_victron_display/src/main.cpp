/*
 * LilyGo T-Display S3 -- standalone Victron Phoenix Inverter monitor.
 *
 * Scans for the Victron BLE "Instant Readout" advertisement (manufacturer
 * ID 0x02E1, Instant Readout marker 0x10), decrypts it (AES-128-CTR) using
 * the inverter's advertisement key, decodes the Inverter fields (device
 * state, alarm, battery voltage, AC apparent power/voltage/current), and
 * shows them on the built-in screen. Runs standalone once flashed -- no
 * Mac, BleuIO dongle, or network connection needed.
 *
 * Protocol details ported from victron_bleuio_scanner.py in this same
 * project, which has the full write-up and was verified against this same
 * physical inverter.
 */

// Touch controller on this board is one of two chip families. CST816/820
// is the more common default; if the touch button never responds after
// flashing, switch this to TOUCH_MODULES_CST_MUTUAL instead (CST328).
#define TOUCH_MODULES_CST_SELF

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <TFT_eSPI.h>
#include <TouchLib.h>
#include <Wire.h>
#include <mbedtls/aes.h>
#include <driver/gpio.h>
#include "pin_config.h"

// ---------------------------------------------------------------------
// Configuration -- fill these in with YOUR inverter's BLE address, Instant
// Readout key (from VictronConnect: Settings -> Product info -> Instant
// readout via Bluetooth -> Show), and Bluetooth pairing PIN (from the same
// screen, or a sticker on the inverter). The values below are placeholders.
// ---------------------------------------------------------------------
static const char *TARGET_MAC = "aa:bb:cc:dd:ee:ff";
static const uint8_t ADVERTISEMENT_KEY[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
static const uint32_t PAIRING_PIN = 123456;

// Same wire format used for the power-mode write in
// victron_inverter_power_control.py: service 306b0001-b081-4037-83dc-e59fcc3cdfd0,
// characteristic 306b0003 (command) and 306b0002 (control/init).
static const char *SERVICE_UUID = "306b0001-b081-4037-83dc-e59fcc3cdfd0";
static const char *CONTROL_CHAR_UUID = "306b0002-b081-4037-83dc-e59fcc3cdfd0";
static const char *COMMAND_CHAR_UUID = "306b0003-b081-4037-83dc-e59fcc3cdfd0";

static const uint16_t VICTRON_MANUFACTURER_ID = 0x02E1;

// ---------------------------------------------------------------------
// AES-128-CTR decryption, matching pycryptodome's
// Counter.new(128, initial_value=iv, little_endian=True): the 128-bit
// counter block is (iv + block_index) written as a little-endian integer
// across all 16 bytes, AES-ECB-encrypted to produce each keystream block.
// ---------------------------------------------------------------------
static void aesCtrDecrypt(const uint8_t *key, uint16_t iv, const uint8_t *ciphertext,
                           size_t len, uint8_t *out) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    size_t offset = 0;
    uint32_t blockIndex = 0;
    while (offset < len) {
        uint8_t counterBlock[16] = {0};
        uint32_t counterValue = (uint32_t)iv + blockIndex;
        counterBlock[0] = counterValue & 0xFF;
        counterBlock[1] = (counterValue >> 8) & 0xFF;
        counterBlock[2] = (counterValue >> 16) & 0xFF;
        counterBlock[3] = (counterValue >> 24) & 0xFF;

        uint8_t keystream[16];
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, counterBlock, keystream);

        size_t chunk = min((size_t)16, len - offset);
        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        offset += chunk;
        blockIndex++;
    }
    mbedtls_aes_free(&aes);
}

// ---------------------------------------------------------------------
// Bit-level reader, LSB to MSB, matching the Python BitReader used to
// unpack Victron's Extra Manufacturer Data payload.
// ---------------------------------------------------------------------
class BitReader {
  public:
    explicit BitReader(const uint8_t *data) : data_(data), index_(0) {}

    uint32_t readUnsignedInt(int numBits) {
        uint32_t value = 0;
        for (int i = 0; i < numBits; i++) {
            int bit = (data_[index_ >> 3] >> (index_ & 7)) & 1;
            value |= (uint32_t)bit << i;
            index_++;
        }
        return value;
    }

    int32_t readSignedInt(int numBits) {
        uint32_t v = readUnsignedInt(numBits);
        if (v & (1UL << (numBits - 1))) {
            return (int32_t)v - (1L << numBits);
        }
        return (int32_t)v;
    }

  private:
    const uint8_t *data_;
    int index_;
};

struct InverterReading {
    bool valid = false;
    uint32_t lastUpdateMs = 0;
    int rssi = 0;
    uint8_t deviceState = 0;
    uint16_t alarm = 0;
    bool hasBatteryVoltage = false;
    float batteryVoltage = 0;
    bool hasAcApparentPower = false;
    uint16_t acApparentPower = 0;
    bool hasAcVoltage = false;
    float acVoltage = 0;
    bool hasAcCurrent = false;
    float acCurrent = 0;
};

static InverterReading g_reading;

// readout_type 0x03 = Inverter. Field layout matches decode_inverter() in
// victron_bleuio_scanner.py.
static void decodeInverter(const uint8_t *decrypted, InverterReading &out) {
    BitReader r(decrypted);

    uint32_t deviceState = r.readUnsignedInt(8);
    uint32_t alarm = r.readUnsignedInt(16);
    int32_t batteryVoltageRaw = r.readSignedInt(16);
    uint32_t acApparentPowerRaw = r.readUnsignedInt(16);
    uint32_t acVoltageRaw = r.readUnsignedInt(15);
    uint32_t acCurrentRaw = r.readUnsignedInt(11);

    out.deviceState = (uint8_t)deviceState;
    out.alarm = (uint16_t)alarm;

    out.hasBatteryVoltage = (batteryVoltageRaw != 0x7FFF);
    out.batteryVoltage = out.hasBatteryVoltage ? batteryVoltageRaw / 100.0f : 0;

    out.hasAcApparentPower = (acApparentPowerRaw != 0xFFFF);
    out.acApparentPower = out.hasAcApparentPower ? (uint16_t)acApparentPowerRaw : 0;

    out.hasAcVoltage = (acVoltageRaw != 0x7FFF);
    out.acVoltage = out.hasAcVoltage ? acVoltageRaw / 100.0f : 0;

    out.hasAcCurrent = (acCurrentRaw != 0x7FF);
    out.acCurrent = out.hasAcCurrent ? acCurrentRaw / 10.0f : 0;
}

// ---------------------------------------------------------------------
// BLE scanning
// ---------------------------------------------------------------------
static NimBLEScan *g_scan;

class VictronScanCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device->getAddress().equals(NimBLEAddress(TARGET_MAC, BLE_ADDR_RANDOM))) {
            return;
        }
        if (!device->haveManufacturerData()) {
            return;
        }

        uint8_t count = device->getManufacturerDataCount();
        for (uint8_t i = 0; i < count; i++) {
            std::string raw = device->getManufacturerData(i);
            if (raw.size() < 3) {
                continue;
            }
            const uint8_t *bytes = reinterpret_cast<const uint8_t *>(raw.data());
            uint16_t companyId = bytes[0] | (bytes[1] << 8);
            if (companyId != VICTRON_MANUFACTURER_ID) {
                continue;
            }

            const uint8_t *payload = bytes + 2;
            size_t payloadLen = raw.size() - 2;
            if (payloadLen < 8 || payload[0] != 0x10) {
                continue;
            }

            uint16_t iv = payload[5] | (payload[6] << 8);
            uint8_t readoutType = payload[4];
            const uint8_t *encryptedData = payload + 7;
            size_t encryptedLen = payloadLen - 7;

            if (encryptedLen < 1 || encryptedData[0] != ADVERTISEMENT_KEY[0]) {
                continue; // key-check byte mismatch -- wrong key or garbled packet
            }

            const uint8_t *ciphertext = encryptedData + 1;
            size_t ciphertextLen = encryptedLen - 1;
            if (ciphertextLen > 32) {
                ciphertextLen = 32; // sanity cap, we only ever need ~11 bytes
            }

            uint8_t decrypted[32];
            aesCtrDecrypt(ADVERTISEMENT_KEY, iv, ciphertext, ciphertextLen, decrypted);

            if (readoutType == 0x03) { // Inverter
                InverterReading reading;
                decodeInverter(decrypted, reading);
                reading.valid = true;
                reading.lastUpdateMs = millis();
                reading.rssi = device->getRSSI();
                g_reading = reading;
            }
            return;
        }
    }
} g_scanCallbacks;

static void renderReading(); // forward declaration, defined below

// ---------------------------------------------------------------------
// BLE client connection + power-mode write.
//
// Wire format matches victron_inverter_power_control.py exactly (verified
// against this same inverter via Wireshark/nRF Sniffer capture): after the
// init/handshake sequence, writing 06 03 82 19 02 00 41 <value> to the
// command characteristic (306b0003) sets the power mode --
// value 0x02 = on, 0x04 = off.
// ---------------------------------------------------------------------
enum class ConnState { IDLE, CONNECTING, PAIRING, SENDING, OK, FAILED };
static ConnState g_connState = ConnState::IDLE;

// -1 = unknown yet (use the passive scan's last known state), 0 = we last
// commanded OFF, 1 = we last commanded ON. See nextActionIsTurnOn() below.
static int g_lastCommandedOn = -1;

struct InitStep {
    const char *charUuid;
    const uint8_t *data;
    size_t len;
};

static const uint8_t INIT_1[] = {0xFA, 0x80, 0xFF};
static const uint8_t INIT_2[] = {0xF9, 0x80};
static const uint8_t INIT_3[] = {0x01};
static const uint8_t INIT_4[] = {0x01};
static const uint8_t INIT_5[] = {0x03, 0x00};
static const uint8_t INIT_6[] = {0x06, 0x00, 0x82, 0x18, 0x93, 0x42, 0x10, 0x27, 0x03, 0x01, 0x03, 0x03};
static const uint8_t INIT_7[] = {0xF9, 0x41};

static const InitStep INIT_SEQUENCE[] = {
    {CONTROL_CHAR_UUID, INIT_1, sizeof(INIT_1)},
    {CONTROL_CHAR_UUID, INIT_2, sizeof(INIT_2)},
    {CONTROL_CHAR_UUID, INIT_3, sizeof(INIT_3)},
    {COMMAND_CHAR_UUID, INIT_4, sizeof(INIT_4)},
    {COMMAND_CHAR_UUID, INIT_5, sizeof(INIT_5)},
    {COMMAND_CHAR_UUID, INIT_6, sizeof(INIT_6)},
    {CONTROL_CHAR_UUID, INIT_7, sizeof(INIT_7)},
};

static const uint8_t POWER_ON_CMD[] = {0x06, 0x03, 0x82, 0x19, 0x02, 0x00, 0x41, 0x02};
static const uint8_t POWER_OFF_CMD[] = {0x06, 0x03, 0x82, 0x19, 0x02, 0x00, 0x41, 0x04};

class VictronClientCallbacks : public NimBLEClientCallbacks {
    void onPassKeyEntry(NimBLEConnInfo &connInfo) override {
        NimBLEDevice::injectPassKey(connInfo, PAIRING_PIN);
    }

    void onAuthenticationComplete(NimBLEConnInfo &connInfo) override {
        if (!connInfo.isBonded() && !connInfo.isEncrypted()) {
            g_connState = ConnState::FAILED;
        }
        // On success we stay in PAIRING state here; testConnectAndSend()
        // moves on to ConnState::SENDING itself once secureConnection()
        // returns, so it can tell a real failure from "not reached yet".
    }
} g_clientCallbacks;

// Connects to the inverter, pairs, sends the requested power-mode command,
// then disconnects. Updates g_connState so the button reflects progress.
static void testConnectAndSend(bool turnOn) {
    g_scan->stop();

    g_connState = ConnState::CONNECTING;
    renderReading();

    NimBLEClient *client = NimBLEDevice::createClient();
    client->setClientCallbacks(&g_clientCallbacks, false);

    NimBLEAddress addr(TARGET_MAC, BLE_ADDR_RANDOM);
    bool connected = client->connect(addr);
    if (!connected) {
        g_connState = ConnState::FAILED;
        NimBLEDevice::deleteClient(client);
        g_scan->start(0, false, true);
        return;
    }

    g_connState = ConnState::PAIRING;
    renderReading();

    // secureConnection() blocks until pairing completes (or fails/times
    // out). onAuthenticationComplete above only flips g_connState on
    // failure; success is confirmed here via the client's connection info.
    client->secureConnection();
    NimBLEConnInfo info = client->getConnInfo();

    if (g_connState != ConnState::FAILED && (info.isBonded() || info.isEncrypted())) {
        g_connState = ConnState::SENDING;
        renderReading();

        NimBLERemoteService *service = client->getService(NimBLEUUID(SERVICE_UUID));
        NimBLERemoteCharacteristic *controlChar =
            service ? service->getCharacteristic(NimBLEUUID(CONTROL_CHAR_UUID)) : nullptr;
        NimBLERemoteCharacteristic *commandChar =
            service ? service->getCharacteristic(NimBLEUUID(COMMAND_CHAR_UUID)) : nullptr;

        if (!service || !controlChar || !commandChar) {
            g_connState = ConnState::FAILED;
        } else {
            bool ok = true;
            for (const InitStep &step : INIT_SEQUENCE) {
                NimBLERemoteCharacteristic *ch =
                    (strcmp(step.charUuid, CONTROL_CHAR_UUID) == 0) ? controlChar : commandChar;
                ok = ch->writeValue(step.data, step.len, true) && ok;
            }
            const uint8_t *cmd = turnOn ? POWER_ON_CMD : POWER_OFF_CMD;
            ok = commandChar->writeValue(cmd, sizeof(POWER_ON_CMD), true) && ok;

            if (ok) {
                g_connState = ConnState::OK;
                g_lastCommandedOn = turnOn ? 1 : 0;
            } else {
                g_connState = ConnState::FAILED;
            }
        }
    } else if (g_connState != ConnState::FAILED) {
        g_connState = ConnState::FAILED;
    }

    client->disconnect();
    NimBLEDevice::deleteClient(client);
    g_scan->start(0, false, true);
}

// ---------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------
TFT_eSPI tft = TFT_eSPI();

#if defined(TOUCH_MODULES_CST_MUTUAL)
TouchLib touch(Wire, PIN_IIC_SDA, PIN_IIC_SCL, CTS328_SLAVE_ADDRESS, PIN_TOUCH_RES);
#elif defined(TOUCH_MODULES_CST_SELF)
TouchLib touch(Wire, PIN_IIC_SDA, PIN_IIC_SCL, CTS820_SLAVE_ADDRESS, PIN_TOUCH_RES);
#else
#error "Define TOUCH_MODULES_CST_SELF or TOUCH_MODULES_CST_MUTUAL"
#endif
static bool g_touchOk = false;

// "Test connection" button, bottom-right of the 320x170 screen.
static const int BUTTON_X0 = 10, BUTTON_Y0 = 250, BUTTON_X1 = 160, BUTTON_Y1 = 300;

static void initTouch() {
    gpio_hold_dis((gpio_num_t)PIN_TOUCH_RES);
    pinMode(PIN_TOUCH_RES, OUTPUT);
    digitalWrite(PIN_TOUCH_RES, LOW);
    delay(500);
    digitalWrite(PIN_TOUCH_RES, HIGH);

    Wire.begin(PIN_IIC_SDA, PIN_IIC_SCL);
    g_touchOk = touch.init();
    Serial.printf("Touch init: %s\n", g_touchOk ? "OK" : "FAILED (try switching TOUCH_MODULES_CST_SELF/MUTUAL)");
}

typedef struct {
    uint8_t cmd;
    uint8_t data[14];
    uint8_t len;
} lcd_cmd_t;

// ST7789V init sequence used by LilyGo's own T-Display-S3 examples --
// needed on some hardware revisions before the panel responds correctly.
static lcd_cmd_t LCD_INIT_SEQUENCE[] = {
    {0x11, {0}, 0 | 0x80},
    {0x3A, {0X05}, 1},
    {0xB2, {0X0B, 0X0B, 0X00, 0X33, 0X33}, 5},
    {0xB7, {0X75}, 1},
    {0xBB, {0X28}, 1},
    {0xC0, {0X2C}, 1},
    {0xC2, {0X01}, 1},
    {0xC3, {0X1F}, 1},
    {0xC6, {0X13}, 1},
    {0xD0, {0XA7}, 1},
    {0xD0, {0XA4, 0XA1}, 2},
    {0xD6, {0XA1}, 1},
    {0xE0, {0XF0, 0X05, 0X0A, 0X06, 0X06, 0X03, 0X2B, 0X32, 0X43, 0X36, 0X11, 0X10, 0X2B, 0X32}, 14},
    {0xE1, {0XF0, 0X08, 0X0C, 0X0B, 0X09, 0X24, 0X2B, 0X22, 0X43, 0X38, 0X15, 0X16, 0X2F, 0X37}, 14},
};

static void initDisplay() {
    pinMode(PIN_POWER_ON, OUTPUT);
    digitalWrite(PIN_POWER_ON, HIGH);

    tft.begin();
    for (size_t i = 0; i < sizeof(LCD_INIT_SEQUENCE) / sizeof(lcd_cmd_t); i++) {
        tft.writecommand(LCD_INIT_SEQUENCE[i].cmd);
        for (int j = 0; j < (LCD_INIT_SEQUENCE[i].len & 0x7f); j++) {
            tft.writedata(LCD_INIT_SEQUENCE[i].data[j]);
        }
        if (LCD_INIT_SEQUENCE[i].len & 0x80) {
            delay(120);
        }
    }
    tft.setRotation(0); // portrait, 170x320
    tft.fillScreen(TFT_BLACK);

    ledcSetup(0, 2000, 8);
    ledcAttachPin(PIN_LCD_BL, 0);
    ledcWrite(0, 255);
}

// Stacked label-above-value layout, sized for the 170px-wide portrait screen.
static void drawValue(int y, const char *label, const char *value, uint16_t color) {
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.setTextFont(2);
    tft.setCursor(4, y);
    tft.print(label);

    tft.setTextColor(color, TFT_BLACK);
    tft.setTextFont(4);
    tft.setCursor(4, y + 16);
    tft.print(value);
}

// The button toggles the inverter's power mode. Prefer the state we last
// commanded ourselves (g_lastCommandedOn, declared above) over the passive
// Instant Readout scan: after sending a command the scan can take a few
// seconds to catch up, and using its stale value would make the button
// send the same command twice in a row before flipping.
static bool nextActionIsTurnOn() {
    if (g_lastCommandedOn != -1) {
        return g_lastCommandedOn == 0;
    }
    return g_reading.valid && g_reading.deviceState == 0;
}

static void drawButton() {
    uint16_t fillColor;
    const char *label;
    switch (g_connState) {
        case ConnState::CONNECTING:
        case ConnState::PAIRING:
        case ConnState::SENDING:
            fillColor = TFT_ORANGE;
            label = "...";
            break;
        case ConnState::OK:
            fillColor = TFT_DARKGREEN;
            label = "OK";
            break;
        case ConnState::FAILED:
            fillColor = TFT_MAROON;
            label = "RETRY";
            break;
        default:
            fillColor = TFT_NAVY;
            label = nextActionIsTurnOn() ? "TURN ON" : "TURN OFF";
            break;
    }
    tft.fillRoundRect(BUTTON_X0, BUTTON_Y0, BUTTON_X1 - BUTTON_X0, BUTTON_Y1 - BUTTON_Y0, 6, fillColor);
    tft.drawRoundRect(BUTTON_X0, BUTTON_Y0, BUTTON_X1 - BUTTON_X0, BUTTON_Y1 - BUTTON_Y0, 6, TFT_WHITE);
    tft.setTextFont(2);
    tft.setTextColor(TFT_WHITE, fillColor);
    int textWidth = tft.textWidth(label);
    tft.setCursor(BUTTON_X0 + (BUTTON_X1 - BUTTON_X0 - textWidth) / 2, BUTTON_Y0 + 8);
    tft.print(label);
}

static void renderReading() {
    tft.fillScreen(TFT_BLACK);

    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.setTextFont(2);
    tft.setCursor(4, 4);
    tft.print("Victron Inverter");

    if (!g_reading.valid) {
        tft.setTextFont(2);
        tft.setCursor(4, 40);
        tft.setTextColor(TFT_ORANGE, TFT_BLACK);
        tft.print("Waiting for signal...");
        drawButton();
        return;
    }

    char buf[32];
    int y = 34;
    const int lineHeight = 52;

    if (g_reading.hasBatteryVoltage) {
        snprintf(buf, sizeof(buf), "%.2f V", g_reading.batteryVoltage);
    } else {
        snprintf(buf, sizeof(buf), "--");
    }
    drawValue(y, "Battery", buf, TFT_WHITE);
    y += lineHeight;

    if (g_reading.hasAcVoltage) {
        snprintf(buf, sizeof(buf), "%.2f V", g_reading.acVoltage);
    } else {
        snprintf(buf, sizeof(buf), "--");
    }
    drawValue(y, "AC Voltage", buf, TFT_WHITE);
    y += lineHeight;

    if (g_reading.hasAcCurrent) {
        snprintf(buf, sizeof(buf), "%.1f A", g_reading.acCurrent);
    } else {
        snprintf(buf, sizeof(buf), "--");
    }
    drawValue(y, "AC Current", buf, TFT_WHITE);
    y += lineHeight;

    if (g_reading.hasAcApparentPower) {
        snprintf(buf, sizeof(buf), "%u VA", g_reading.acApparentPower);
    } else {
        snprintf(buf, sizeof(buf), "--");
    }
    drawValue(y, "AC Power", buf, TFT_WHITE);

    drawButton();
}

// ---------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    initDisplay();
    initTouch();

    NimBLEDevice::init("");
    NimBLEDevice::setSecurityAuth(true, true, false); // bonding, MITM, legacy pairing (not secure connections)
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_KEYBOARD_ONLY);

    g_scan = NimBLEDevice::getScan();
    g_scan->setScanCallbacks(&g_scanCallbacks);
    g_scan->setActiveScan(true);
    g_scan->setInterval(100);
    g_scan->setWindow(100);
    g_scan->start(0, false, true); // duration=0 -> scan indefinitely
}

static bool touchInsideButton() {
    if (!g_touchOk || !touch.read()) {
        return false;
    }
    TP_Point p = touch.getPoint(0);

    // The touch panel reports raw coordinates in the display's native
    // portrait orientation (170 wide x 320 tall), which now matches
    // tft.setRotation(0) directly -- no transform needed (unlike the
    // landscape rotation(3) case, which needed screenX=319-y, screenY=x).
    // If the button doesn't respond, this mapping may need swapping --
    // see git history for the landscape version's derivation method.
    int screenX = p.x;
    int screenY = p.y;

    return screenX >= BUTTON_X0 && screenX <= BUTTON_X1 && screenY >= BUTTON_Y0 && screenY <= BUTTON_Y1;
}

static const uint32_t RESULT_DISPLAY_MS = 3000; // how long OK/FAILED stays on the button

void loop() {
    static bool wasPressed = false;
    static uint32_t resultShownAtMs = 0;

    if ((g_connState == ConnState::OK || g_connState == ConnState::FAILED) &&
        millis() - resultShownAtMs > RESULT_DISPLAY_MS) {
        g_connState = ConnState::IDLE;
    }

    renderReading();

    bool pressed = touchInsideButton();
    bool busy = g_connState == ConnState::CONNECTING || g_connState == ConnState::PAIRING ||
                g_connState == ConnState::SENDING;
    if (pressed && !wasPressed && !busy) {
        testConnectAndSend(nextActionIsTurnOn());
        resultShownAtMs = millis();
        renderReading();
    }
    wasPressed = pressed;

    delay(200);
}
