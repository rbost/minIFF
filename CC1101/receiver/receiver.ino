#include <Arduino.h>
#include <cc1101.h>
#include <EEPROM.h>
#include <WiFi.h>
#include <WebServer.h>

#include <Ed25519.h>
#include <Curve25519.h>
#include <BLAKE2s.h>
#include <ChaChaPoly.h>
#include <RNG.h>

#include "base64.hpp"
#include "html.h"


using namespace CC1101;
using ConstSharedKey = const uint8_t*;

enum Mode { SetupMode,
            RunningMode };

Mode mode = RunningMode;


const char* ssid = "minIFF Setup";  // Enter SSID here
const char* password = "setup";     // Enter Password here (7+ characters to be valid)

#define BUTTON_PIN 21  // GPIO21 pin connected to button

//Radio radio(/* cs pin */ 5);
Radio radio(/*cs*/ 5, /*clk*/ 18, /*miso*/ 19, /*mosi*/ 23);

IPAddress local_ip(192, 168, 1, 1);
IPAddress gateway(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);

WebServer server(80);


uint8_t rnd_seed[64];
uint64_t drone_id;

uint8_t sender_sig_public_key[32];
uint8_t sender_enc_public_key[32];
uint8_t static_private_key[32];
uint8_t static_public_key[32];


// const uint8_t sender_sig_public_key[32] = { 0x85, 0x7F, 0x78, 0xB7, 0x70, 0xF5, 0xF7, 0xCC, 0xA, 0xC6, 0x49, 0x6B, 0xCA, 0xF2, 0x8E, 0xB4, 0x59, 0x99, 0xAA, 0x39, 0x1C, 0x91, 0xC1, 0xAC, 0xA6, 0x94, 0xDE, 0x6E, 0xB3, 0x83, 0xF9, 0x58 };
// const uint8_t sender_enc_public_key[32] = { 0x66, 0xE1, 0x32, 0x9, 0x45, 0x8E, 0x7F, 0x25, 0xE7, 0x99, 0x8A, 0x17, 0xD1, 0xCA, 0x32, 0x0, 0x28, 0x48, 0xB2, 0x89, 0x0, 0xD, 0xC0, 0x32, 0x21, 0x1A, 0x73, 0x9A, 0x53, 0x8A, 0xCD, 0x4F };
// const uint8_t static_private_key[32] = { 0xF8, 0x76, 0x81, 0x4A, 0x5F, 0xFE, 0x57, 0x90, 0x5E, 0x99, 0xF1, 0x61, 0x68, 0x40, 0xF0, 0xE, 0x94, 0x54, 0xF7, 0x56, 0x2E, 0xD5, 0x53, 0x55, 0x3E, 0x1C, 0xFD, 0x85, 0xCE, 0x6B, 0xC3, 0x7D };
// const uint8_t static_public_key[32] = { 0x68, 0xFF, 0x9B, 0x21, 0xF, 0x5C, 0xD5, 0x6, 0x91, 0x93, 0xF7, 0xE4, 0x1B, 0xAA, 0xB5, 0x53, 0xEA, 0xD9, 0x90, 0xE4, 0x97, 0x6C, 0xE9, 0xC, 0x98, 0x35, 0x80, 0xA7, 0xD8, 0x65, 0x74, 0x03 };

// sender public keys (base64)
// sig: hX94t3D198wKxklryvKOtFmZqjkckcGsppTebrOD+Vg=
// enc: ZuEyCUWOfyXnmYoX0coyAChIsokADcAyIRpzmlOKzU8=

// test keypairs (bytes/base64)

// sk
// 0xF8, 0x76, 0x81, 0x4A, 0x5F, 0xFE, 0x57, 0x90, 0x5E, 0x99, 0xF1, 0x61, 0x68, 0x40, 0xF0, 0xE, 0x94, 0x54, 0xF7, 0x56, 0x2E, 0xD5, 0x53, 0x55, 0x3E, 0x1C, 0xFD, 0x85, 0xCE, 0x6B, 0xC3, 0x7D
// +HaBSl/+V5BemfFhaEDwDpRU91Yu1VNVPhz9hc5rw30=
// pk
// 0x68, 0xFF, 0x9B, 0x21, 0xF, 0x5C, 0xD5, 0x6, 0x91, 0x93, 0xF7, 0xE4, 0x1B, 0xAA, 0xB5, 0x53, 0xEA, 0xD9, 0x90, 0xE4, 0x97, 0x6C, 0xE9, 0xC, 0x98, 0x35, 0x80, 0xA7, 0xD8, 0x65, 0x74, 0x03
// aP+bIQ9c1QaRk/fkG6q1U+rZkOSXbOkMmDWAp9hldAM=

// sk
// 0x58, 0x35, 0xBC, 0x5A, 0xEC, 0xB3, 0xC5, 0x57, 0xC2, 0x33, 0xE7, 0x21, 0x5F, 0xEE, 0xB4, 0x97, 0xEF, 0x38, 0x54, 0xE9, 0xCA, 0x48, 0x96, 0x22, 0x9C, 0x66, 0x48, 0xCF, 0xF2, 0xEA, 0x44, 0x6C
// WDW8WuyzxVfCM+chX+60l+84VOnKSJYinGZIz/LqRGw=
// pk
// 0x6C, 0x3, 0x79, 0x52, 0xEB, 0x9A, 0xE, 0xC2, 0x49, 0xBB, 0xB, 0xA7, 0x2C, 0xCE, 0x1E, 0xAD, 0xC7, 0x91, 0xC6, 0xBF, 0xBC, 0x61, 0x91, 0x15, 0xC4, 0xE0, 0x93, 0xCF, 0x3A, 0xAF, 0x1E, 0x54
// bAN5UuuaDsJJuwunLM4erceRxr+8YZEVxOCTzzqvHlQ=



// configuration URL for drone id 123 :
// http://192.168.1.1/setup?seed=c0p4pmWhWEeYTbuEywlUIcl7oS1o0z4KtZjVq6ZiaJmh4v15FMwsyt7x24aJfRe37CGYRzwOc31zxlUOO8GLoQ%3D%3D&sk=%2BHaBSl%2F%2BV5BemfFhaEDwDpRU91Yu1VNVPhz9hc5rw30%3D&pk=aP%2BbIQ9c1QaRk%2FfkG6q1U%2BrZkOSXbOkMmDWAp9hldAM%3D&id=123&interr_sig_pk=hX94t3D198wKxklryvKOtFmZqjkckcGsppTebrOD%2BVg%3D&interr_enc_pk=ZuEyCUWOfyXnmYoX0coyAChIsokADcAyIRpzmlOKzU8%3D

// configuration URL for drone id 678 :
// http://192.168.1.1/setup?seed=aN%2FWieL8jO5yWyxZ5OAyBXEiRU7nf57C1i6nZLPyZAEbvM%2Fh1z4Ogu35cbSFZRzErtRUYCDNsyru6vaG4WPQhQ%3D%3D&sk=WDW8WuyzxVfCM%2BchX%2B60l%2B84VOnKSJYinGZIz%2FLqRGw%3D&pk=bAN5UuuaDsJJuwunLM4erceRxr%2B8YZEVxOCTzzqvHlQ%3D&id=678&interr_sig_pk=hX94t3D198wKxklryvKOtFmZqjkckcGsppTebrOD%2BVg%3D&interr_enc_pk=ZuEyCUWOfyXnmYoX0coyAChIsokADcAyIRpzmlOKzU8%3D


void setup() {
  Serial.begin(115200);
  delay(3000);
  Serial.println(F("Starting ..."));
  delay(1000);

  if (radio.begin() == STATUS_CHIP_NOT_FOUND) {
    Serial.println(F("Chip not found!"));
    while (true) { delay(1000); }
  }

  radio.setModulation(MOD_ASK_OOK);
  radio.setFrequency(433.8);
  radio.setDataRate(10);
  radio.setOutputPower(10);

  radio.setPacketLengthMode(PKT_LEN_MODE_VARIABLE);
  radio.setAddressFilteringMode(ADDR_FILTER_MODE_NONE);
  radio.setPreambleLength(64);
  radio.setSyncWord(0x1234);
  radio.setSyncMode(SYNC_MODE_16_16);
  radio.setCrc(true);
  radio.setDataWhitening(true);
  radio.setManchester(false);
  radio.setFEC(false);

  RNG.begin("minIFF receiver");
  RNG.stir(rnd_seed, sizeof(rnd_seed));

  EEPROM.begin(sizeof(rnd_seed) + sizeof(drone_id) + sizeof(sender_sig_public_key) + sizeof(sender_enc_public_key) + sizeof(static_private_key) + sizeof(static_public_key));

  // initialize the pushbutton pin as an pull-up input
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  if (digitalRead(BUTTON_PIN) == 0) {  // the button is pushed
    // enter setup mode
    mode = SetupMode;
    Serial.println("Setup Mode");
    startSetupMode();
  } else {
    // enter run mode
    mode = RunningMode;
    Serial.println("Running Mode");
    startRunningMode();
  }
}

void printHex(const uint8_t* buffer, size_t len) {
  if (len > 0) {
    Serial.print("0x");
    Serial.print(*(buffer), HEX);
  }
  for (size_t i = 1; i < len; i++) {
    Serial.print(", 0x");
    Serial.print(*(buffer + i), HEX);
  }
}
void printHexLn(const uint8_t* buffer, size_t len) {
  printHex(buffer, len);
  Serial.println();
}

void printStatus(Status status) {
  if (status == STATUS_OK) {
    Serial.println(F("[OK]"));
  } else if (status == STATUS_CRC_MISMATCH) {
    Serial.println(F("CRC mismatch!"));
  } else {
    Serial.print("[ERROR ");
    Serial.print(status);
    Serial.println("]");
  }
}

void printRadioStats(Status status) {
  if (status != STATUS_OK) {
    return;
  }
  Serial.print(F("RSSI: "));
  Serial.print(radio.getRSSI());
  Serial.println(F(" dBm"));

  Serial.print(F("LQI: "));
  Serial.println(radio.getLQI());
}



uint8_t position[64] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };


void loop() {
  switch (mode) {
    case RunningMode:
      return runningModeLoop();
    case SetupMode:
      return setupModeLoop();
  }
}

void runningModeLoop() {
  uint8_t challenge[8 + 32 + 64] = { 0 };
  size_t read;

  Serial.println(F("Receiving ..."));
  Status status = radio.receive((uint8_t*)challenge, sizeof(challenge), &read);

  printStatus(status);

  if (status == STATUS_OK) {

    Serial.print(F("Received data: "));
    printHexLn(challenge, sizeof(challenge));

    const uint64_t session_id = *challenge;

    Serial.print(F("Length: "));
    Serial.println(read);
    printRadioStats(status);

    if (read != 8 + 32 + 64) {
      Serial.println("[ERROR] Invalid challenge size: " + String(read));
    }

    bool sig_verified = Ed25519::verify(challenge + 8 + 32, sender_sig_public_key, challenge, 8 + 32);

    // if (sig_verified) {
    //   Serial.println(F("Valid signature"));
    // } else {
    //   Serial.println(F("Invalid signature"));
    //   return;
    // }

    uint8_t* sender_ephemeral_public_key = challenge + 8;

    uint8_t ephemeral_private_key[32];
    uint8_t ephemeral_public_key[32];
    generateX25519Keypair(ephemeral_private_key, ephemeral_public_key);

    uint8_t ee[32];
    uint8_t ss[32];
    uint8_t se[32];
    uint8_t es[32];

    if (!combineX25519Keys(ephemeral_private_key, sender_ephemeral_public_key, ee)) {  // drone eph, interr eph
      Serial.println("[ERROR] Invalid ee");
    }
    if (!combineX25519Keys(static_private_key, sender_enc_public_key, ss)) {  // drone static, interr static
      Serial.println("[ERROR] Invalid ss");
    }
    if (!combineX25519Keys(ephemeral_private_key, sender_enc_public_key, se)) {  // drone eph, interr static
      Serial.println("[ERROR] Invalid se");
    }
    if (!combineX25519Keys(static_private_key, sender_ephemeral_public_key, es)) {  // drone static, interr eph
      Serial.println("[ERROR] Invalid es");
    }

    // Serial.println(F("ee : "));
    // printHexLn(ee, sizeof(ee));
    // Serial.println(F("ss : "));
    // printHexLn(ss, sizeof(ss));
    // Serial.println(F("se : "));
    // printHexLn(se, sizeof(se));
    // Serial.println(F("es : "));
    // printHexLn(es, sizeof(es));
    // Serial.flush();

    uint8_t enc_key1[32];
    uint8_t enc_key2[32];
    uint8_t iv[32] = { 0x00 };

    const ConstSharedKey shared_keys1[2] = { ee, se };

    deriveKey(nullptr, shared_keys1, 2, enc_key1);

    Serial.print(F("Derived key 1 : "));
    printHexLn(enc_key1, sizeof(enc_key1));
    Serial.flush();


    const ConstSharedKey shared_keys2[2] = { ss, es };
    deriveKey(enc_key1, shared_keys2, 2, enc_key2);

    Serial.print(F("Derived key 2 : "));
    printHexLn(enc_key2, sizeof(enc_key2));
    Serial.flush();

    Serial.println("Session id : " + String(session_id));
    Serial.println("Drone id : " + String(drone_id));
    Serial.flush();


    ChaChaPoly enc;

    enc.clear();
    enc.setKey(enc_key1, 32);
    enc.setIV(iv, 32);
    enc.addAuthData(&session_id, sizeof(session_id));
    enc.addAuthData(ephemeral_public_key, sizeof(ephemeral_public_key));
    enc.addAuthData(sender_ephemeral_public_key, 32);

    uint8_t enc_id[8];
    enc.encrypt(enc_id, reinterpret_cast<const uint8_t*>(&drone_id), sizeof(drone_id));

    uint8_t tag_id[16];
    enc.computeTag(tag_id, 16);



    enc.clear();
    enc.setKey(enc_key2, 32);
    enc.setIV(iv, 32);
    enc.addAuthData(tag_id, 16);  // to have a strong link with the previous part of the message

    uint8_t enc_pos[64];
    enc.encrypt(enc_pos, position, sizeof(position));
    uint8_t pos_tag[16];
    enc.computeTag(pos_tag, 16);

    uint8_t message[8 /*session_id*/ + 32 /*ephemeral_public_key*/ + 8 /*enc id*/ + 16 /* tag 1*/ + 64 /* enc pos*/ + 16 /* tag 2*/];

    memcpy(message, &session_id, sizeof(session_id));
    memcpy(message + 8, ephemeral_public_key, sizeof(ephemeral_public_key));
    memcpy(message + 40, enc_id, sizeof(enc_id));
    memcpy(message + 48, tag_id, sizeof(tag_id));
    memcpy(message + 64, enc_pos, sizeof(enc_pos));
    memcpy(message + 128, pos_tag, sizeof(pos_tag));


    Serial.print(F("Transmitting: "));
    printHexLn(message, sizeof(message));

    status = radio.transmit(message, sizeof(message));

    printStatus(status);

    Serial.println();
  }
}

void startSetupMode() {
  WiFi.softAP(ssid, password);
  WiFi.softAPConfig(local_ip, gateway, subnet);
  delay(100);

  Serial.println("WiFi started.\nSSID: " + String(ssid) + "\nPassword: " + String(password));

  server.on("/", handle_OnConnect);
  server.on("/setup", handle_OnSetup);
  server.onNotFound(handle_NotFound);

  server.begin();

  Serial.println("HTTP server started at " + String(WiFi.softAPIP()));
}

void handle_OnConnect() {
  server.send(200, "text/html", String(HTML_HEADER) + String(HTML_SETUP));
}

// void handle_OnSetup(WiFiClient& client, const String& method, const String& request, const QueryParams& params, const String& jsonData) {
void handle_OnSetup() {
  int args_count = server.args();
  bool set_seed = false;
  bool set_sk = false;
  bool set_pk = false;
  bool set_id = false;
  bool set_interr_sig_pk = false;
  bool set_interr_enc_pk = false;

  for (int i = 0; i < args_count; i++) {
    // Serial.println(server.argName(i));
    // Serial.println(server.arg(i));

    if (server.argName(i) == "seed") {

      unsigned int len = decode_base64_length((const unsigned char*)server.arg(i).c_str());
      if (len != 64) {
        Serial.println("Invalid seed length: " + String(len));
      } else {
        set_seed = true;
      }
      decode_base64((const unsigned char*)server.arg(i).c_str(), rnd_seed);
      // printHexLn(rnd_seed, 64);
    } else if (server.argName(i) == "sk") {
      unsigned int len = decode_base64_length((const unsigned char*)server.arg(i).c_str());
      if (len != 32) {
        Serial.println("Invalid sk length: " + String(len));
      } else {
        set_sk = true;
      }
      decode_base64((const unsigned char*)server.arg(i).c_str(), static_private_key);
      // printHexLn(static_private_key, 32);
    } else if (server.argName(i) == "pk") {
      unsigned int len = decode_base64_length((const unsigned char*)server.arg(i).c_str());
      if (len != 32) {
        Serial.println("Invalid pk length: " + String(len));
      } else {
        set_pk = true;
      }
      decode_base64((const unsigned char*)server.arg(i).c_str(), static_public_key);
      // printHexLn(static_public_key, 32);

    } else if (server.argName(i) == "id") {
      drone_id = server.arg(i).toInt();
      Serial.println("Drone identifier: " + String(drone_id));
      set_id = true;
    } else if (server.argName(i) == "interr_sig_pk") {
      unsigned int len = decode_base64_length((const unsigned char*)server.arg(i).c_str());
      if (len != 32) {
        Serial.println("Invalid seed length: " + String(len));
      } else {
        set_interr_sig_pk = true;
      }
      decode_base64((const unsigned char*)server.arg(i).c_str(), sender_sig_public_key);
      // printHexLn(sender_sig_public_key, 32);

    } else if (server.argName(i) == "interr_enc_pk") {
      unsigned int len = decode_base64_length((const unsigned char*)server.arg(i).c_str());
      if (len != 32) {
        Serial.println("Invalid seed length: " + String(len));
      } else {
        set_interr_enc_pk = true;
      }
      decode_base64((const unsigned char*)server.arg(i).c_str(), sender_enc_public_key);
      // printHexLn(sender_enc_public_key, 32);

    } else {
      Serial.println("Unknown parameter");
    }
  }

  if (set_seed && set_sk && set_pk && set_id && set_interr_sig_pk && set_interr_enc_pk) {
    writeConfigToEEPROM();
    server.send(200, "text/html", String(HTML_HEADER) + String(HTML_COMPLETED_SETUP));

    readConfigFromEEPROM();
  } else {
    // setup failed
    server.send(200, "text/html", String(HTML_HEADER) + String(HTML_FAILED_SETUP));
  }
}


void handle_NotFound() {
  server.send(404, "text/plain", "Not found");
}


void setupModeLoop() {
  server.handleClient();
}


void startRunningMode() {
  readConfigFromEEPROM();
}

void printConfig() {
  Serial.println("Config: ");

  Serial.println("Seed: ");
  printHexLn(rnd_seed, 64);
  Serial.println("Identifier: ");
  Serial.println(String(drone_id));
  Serial.println("Interrogator signature pk: ");
  printHexLn(sender_sig_public_key, 32);
  Serial.println("Interrogator encryption pk: ");
  printHexLn(sender_enc_public_key, 32);
  Serial.println("Drone private key: ");
  printHexLn(static_private_key, 32);
  Serial.println("Drone public key: ");
  printHexLn(static_public_key, 32);
}

void writeConfigToEEPROM() {
  Serial.print("Write ");
  printConfig();

  int eeAddress = 0;

  // seed
  EEPROM.put(eeAddress, rnd_seed);
  eeAddress += sizeof(rnd_seed);

  // drone id
  EEPROM.put(eeAddress, drone_id);
  eeAddress += sizeof(drone_id);

  EEPROM.put(eeAddress, sender_sig_public_key);
  eeAddress += sizeof(sender_sig_public_key);

  EEPROM.put(eeAddress, sender_enc_public_key);
  eeAddress += sizeof(sender_enc_public_key);

  EEPROM.put(eeAddress, static_private_key);
  eeAddress += sizeof(static_private_key);

  EEPROM.put(eeAddress, static_public_key);
  eeAddress += sizeof(static_public_key);

  EEPROM.commit();
}

void readConfigFromEEPROM() {
  int eeAddress = 0;

  // seed
  EEPROM.get(eeAddress, rnd_seed);
  eeAddress += sizeof(rnd_seed);

  // drone id
  EEPROM.get(eeAddress, drone_id);
  eeAddress += sizeof(drone_id);

  EEPROM.get(eeAddress, sender_sig_public_key);
  eeAddress += sizeof(sender_sig_public_key);

  EEPROM.get(eeAddress, sender_enc_public_key);
  eeAddress += sizeof(sender_enc_public_key);

  EEPROM.get(eeAddress, static_private_key);
  eeAddress += sizeof(static_private_key);

  EEPROM.get(eeAddress, static_public_key);
  eeAddress += sizeof(static_public_key);

  Serial.print("Read ");
  printConfig();
}

void generateX25519Keypair(uint8_t sk[32], uint8_t pk[32]) {
  Curve25519::dh1(pk, sk);
}

bool combineX25519Keys(const uint8_t sk[32], const uint8_t pk[32], uint8_t res[32]) {

  uint8_t tmp_sk[32];
  memcpy(res, pk, 32);
  memcpy(tmp_sk, sk, 32);

  return Curve25519::dh2(res, tmp_sk);
}


// derive key from a set of X25519 keys
void deriveKey(const uint8_t chaining_key[32], const ConstSharedKey* shared_keys, size_t shared_keys_num, uint8_t key[32]) {
  // void deriveKey(const uint8_t ee[32], const uint8_t ss[32], const uint8_t se[32], const uint8_t es[32], uint8_t key[32]) {
  // Use Blake2s as a KDF. Not great (as it is dependent on Blake2's properties), but simpler and more efficient than using HKDF)
  BLAKE2s hash;

  if (chaining_key == nullptr) {
    hash.reset(nullptr, 0);
  } else {
    hash.reset(chaining_key, 32);
  }
  for (size_t i = 0; i < shared_keys_num; i++) {
    hash.update(shared_keys[i], 32);
  }
  hash.finalize(key, 32);
}