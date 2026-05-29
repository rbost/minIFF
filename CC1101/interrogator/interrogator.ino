#include <Arduino.h>
#include <cc1101.h>

#include <Ed25519.h>
#include <Curve25519.h>
#include <BLAKE2s.h>
#include <ChaChaPoly.h>
#include <RNG.h>

using namespace CC1101;
using ConstSharedKey = const uint8_t*;

Radio radio(/*cs*/ 5, /*clk*/ 18, /*miso*/ 19, /*mosi*/ 23);

const uint8_t sender_sig_private_key[32] = { 0xa8, 0x43, 0x8c, 0x9a, 0xc3, 0xcd, 0xfd, 0x4c, 0x7a, 0x38, 0xe0, 0xae, 0x95, 0x05, 0x9a, 0xf7, 0x26, 0xc4, 0x4b, 0x80, 0x25, 0x13, 0x50, 0x4b, 0xbf, 0x0c, 0x26, 0xc2, 0x0f, 0x65, 0x0c, 0x36 };
const uint8_t sender_sig_public_key[32] = { 0x85, 0x7F, 0x78, 0xB7, 0x70, 0xF5, 0xF7, 0xCC, 0xA, 0xC6, 0x49, 0x6B, 0xCA, 0xF2, 0x8E, 0xB4, 0x59, 0x99, 0xAA, 0x39, 0x1C, 0x91, 0xC1, 0xAC, 0xA6, 0x94, 0xDE, 0x6E, 0xB3, 0x83, 0xF9, 0x58 };

const uint8_t sender_enc_private_key[32] = { 0x20, 0x26, 0xA3, 0x45, 0xFB, 0x93, 0xF0, 0x7A, 0x6D, 0x6F, 0xA9, 0x31, 0x52, 0x97, 0x4, 0x42, 0x96, 0x86, 0xF, 0x43, 0xEE, 0x34, 0x7D, 0xB0, 0xE1, 0x28, 0x4A, 0x50, 0xCC, 0x4B, 0x7E, 0x6D };
const uint8_t sender_enc_public_key[32] = { 0x66, 0xE1, 0x32, 0x9, 0x45, 0x8E, 0x7F, 0x25, 0xE7, 0x99, 0x8A, 0x17, 0xD1, 0xCA, 0x32, 0x0, 0x28, 0x48, 0xB2, 0x89, 0x0, 0xD, 0xC0, 0x32, 0x21, 0x1A, 0x73, 0x9A, 0x53, 0x8A, 0xCD, 0x4F };


const uint8_t static_drone_public_key[32] = { 0x68, 0xFF, 0x9B, 0x21, 0xF, 0x5C, 0xD5, 0x6, 0x91, 0x93, 0xF7, 0xE4, 0x1B, 0xAA, 0xB5, 0x53, 0xEA, 0xD9, 0x90, 0xE4, 0x97, 0x6C, 0xE9, 0xC, 0x98, 0x35, 0x80, 0xA7, 0xD8, 0x65, 0x74, 0x03 };

// should be set externally
const uint8_t rnd_seed[64] = { 0xfe, 0x1c, 0xc4, 0x9c, 0x32, 0x76, 0xac, 0x96, 0x5e, 0x9a, 0x97, 0x17, 0x72, 0x6e, 0x5d, 0x6e, 0x47, 0x34, 0x07, 0x4d, 0x0f, 0x2f, 0x34, 0xdb, 0xf3, 0xaa, 0x71, 0x9b, 0x87, 0x0c, 0x18, 0x89, 0x27, 0xbf, 0xdb, 0xcf, 0xdf, 0xad, 0x79, 0x25, 0xbb, 0xd3, 0xaa, 0x2a, 0x9d, 0x22, 0xc0, 0x4e, 0xa3, 0x5c, 0xcb, 0xe9, 0xed, 0xbe, 0xac, 0x22, 0xb4, 0xab, 0x79, 0x70, 0x8b, 0xd3, 0x81, 0xf1 };


struct IFFRecord {
  uint64_t identifier;
  uint8_t static_public_key[32];
};

constexpr size_t kNDroneRecords = 2;

const IFFRecord drone_records[kNDroneRecords] = {
  { 123,
    { 0x68, 0xFF, 0x9B, 0x21, 0xF, 0x5C, 0xD5, 0x6, 0x91, 0x93, 0xF7, 0xE4, 0x1B, 0xAA, 0xB5, 0x53, 0xEA, 0xD9, 0x90, 0xE4, 0x97, 0x6C, 0xE9, 0xC, 0x98, 0x35, 0x80, 0xA7, 0xD8, 0x65, 0x74, 0x03 } },
  { 678,
    { 0x6C, 0x3, 0x79, 0x52, 0xEB, 0x9A, 0xE, 0xC2, 0x49, 0xBB, 0xB, 0xA7, 0x2C, 0xCE, 0x1E, 0xAD, 0xC7, 0x91, 0xC6, 0xBF, 0xBC, 0x61, 0x91, 0x15, 0xC4, 0xE0, 0x93, 0xCF, 0x3A, 0xAF, 0x1E, 0x54 } }
};

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

  RNG.begin("minIFF interrogator");
  RNG.stir(rnd_seed, sizeof(rnd_seed));

  /// Test
  // testDH();
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
  Serial.print(F("RSSI: "));
  Serial.print(radio.getRSSI());
  Serial.println(F(" dBm"));

  Serial.print(F("LQI: "));
  Serial.println(radio.getLQI());
}

uint64_t session_counter = 1;


void loop() {
  uint8_t sender_ephemeral_private_key[32];
  uint8_t sender_ephemeral_public_key[32];

  uint64_t session_id = session_counter++;

  sendChallenge(session_id, sender_ephemeral_private_key,
                sender_ephemeral_public_key);
  // get the response
  receiveChallengeResponse(session_id, sender_ephemeral_private_key,
                           sender_ephemeral_public_key);
  delay(10 * 1000);
}

void sendChallenge(uint64_t session_id, uint8_t sender_ephemeral_private_key[32],
                   uint8_t sender_ephemeral_public_key[32]) {
  String challenge_string = "challenge #" + String(session_id);

  generateX25519Keypair(sender_ephemeral_private_key, sender_ephemeral_public_key);

  // Serial.println(F("[Ephemeral private key] : "));
  // printHexLn(sender_ephemeral_private_key, 32);
  // Serial.println(F("[Ephemeral public key] : "));
  // printHexLn(sender_ephemeral_public_key, 32);

  uint8_t challenge[8 + 32 + 64] = { 0 };  // sizeof(session_id) + sizeof(sender_ephemeral_public_key) + signature
  memcpy(challenge, &session_id, 8);
  memcpy(challenge + 8, sender_ephemeral_public_key, 32);
  Ed25519::sign(challenge + 8 + 32, sender_sig_private_key, sender_sig_public_key, challenge, 8 + 32);


  Serial.print(F("Transmitting challenge: "));
  Serial.println(challenge_string);
  printHex(challenge, sizeof(challenge));
  Serial.println();

  Status status = radio.transmit(challenge, sizeof(challenge));

  printStatus(status);
}

void receiveChallengeResponse(uint64_t session_id, const uint8_t sender_ephemeral_private_key[32],
                              const uint8_t sender_ephemeral_public_key[32]) {
  uint8_t response[8 /*session_id*/ + 32 /*ephemeral_public_key*/ + 8 /*enc id*/ + 16 /* tag 1*/ + 64 /* enc pos*/ + 16 /* tag 2*/];
  // uint8_t response[8 /*session_id*/ + 32 /*ephemeral_public_key*/ + 8 /*enc id*/ + 16 /* tag 1*/];
  size_t read;

  Serial.println(F("Receiving ..."));
  Status status = radio.receive(response, sizeof(response), &read);

  printStatus(status);

  if (status == STATUS_OK) {
    Serial.print(F("Received data: "));
    printHexLn(response, sizeof(response));

    Serial.print(F("Length: "));
    Serial.println(read);

    printRadioStats(status);

    if (read != sizeof(response)) {
      Serial.println("[ERROR] Invalid response size: " + String(read));
    }

    uint64_t received_session_id = *reinterpret_cast<uint64_t*>(response);



    if (session_id != received_session_id) {
      Serial.println("[ERROR] Invalid session id: " + String(received_session_id));
    }

    const uint8_t* ephemeral_public_key = response + 8;
    uint8_t se[32];
    uint8_t ee[32];

    uint8_t enc_key1[32];
    uint8_t iv[32] = { 0x00 };

    if (!combineX25519Keys(sender_enc_private_key, ephemeral_public_key, se)) {  // drone eph, interr static
      Serial.println("[ERROR] Invalid se");
    }
    if (!combineX25519Keys(sender_ephemeral_private_key, ephemeral_public_key, ee)) {  // drone eph, interr eph
      Serial.println("[ERROR] Invalid ee");
    }

    const ConstSharedKey shared_keys1[2] = { ee, se };

    deriveKey(nullptr, shared_keys1, 2, enc_key1);

    Serial.print(F("Derived key 1 : "));
    printHexLn(enc_key1, sizeof(enc_key1));
    Serial.flush();

    // decrypt the first part of the message, containing the drone id
    ChaChaPoly dec;

    dec.clear();  // there seems to be some kind of memory initialization bug in the crypto library. If we do not clear dec, the first iteration of the loop fails
    dec.setKey(enc_key1, 32);
    dec.setIV(iv, 32);
    dec.addAuthData(&session_id, sizeof(session_id));
    dec.addAuthData(ephemeral_public_key, 32);
    dec.addAuthData(sender_ephemeral_public_key, 32);

    uint64_t receiver_id;  // = *reinterpret_cast<uint64_t*>(response + 8);
    const uint8_t* enc_id = response + 8 + 32;
    dec.decrypt(reinterpret_cast<uint8_t*>(&receiver_id), enc_id, 8);

    const uint8_t* tag1 = enc_id + 8;
    bool dec_success1 = dec.checkTag(tag1, 16);

    if (!dec_success1) {
      Serial.println(F("[ERROR] : Partial decryption failed."));
      return;
    }

    Serial.println("Session id : " + String(session_id));
    Serial.println("Drone id : " + String(receiver_id));
    Serial.flush();

    // here, we should be looking for the key in a directory using receiver_id, but this is a proof of concept
    const uint8_t* static_public_key = find_drone_key(receiver_id);

    if (static_public_key == nullptr) {
      Serial.println("[ERROR] Invalid identifier. Abort.");
      return;
    }

    uint8_t ss[32];
    uint8_t es[32];



    if (!combineX25519Keys(sender_enc_private_key, static_public_key, ss)) {  // drone static, interr static
      Serial.println("[ERROR] Invalid ss");
    }
    if (!combineX25519Keys(sender_ephemeral_private_key, static_public_key, es)) {  // drone static, interr eph
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

    uint8_t enc_key2[32];
    const ConstSharedKey shared_keys[2] = { ss, es };
    deriveKey(enc_key1, shared_keys, 2, enc_key2);
    Serial.print(F("Derived key 2: "));
    printHexLn(enc_key2, sizeof(enc_key2));

    const uint8_t* ct = tag1 + 16;
    const uint8_t* tag2 = ct + 64;
    uint8_t position[64] = { 0x00 };


    dec.clear();  // there seems to be some kind of memory initialization bug in the crypto library. If we do not clear dec, the first iteration of the loop fails
    dec.setKey(enc_key2, 32);
    dec.setIV(iv, 32);
    dec.addAuthData(tag1, 16);

    dec.decrypt(position, ct, 64);
    Serial.println(F("Position : "));
    printHexLn(position, 64);

    bool dec_success = dec.checkTag(tag2, 16);

    if (dec_success) {
      Serial.println(F("Decryption succeeded."));
    } else {
      Serial.println(F("[ERROR] : Decryption failed."));
    }
  }

  Serial.println();
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

void testDH() {
  static uint8_t alice_pk[32];
  static uint8_t alice_sk[32];
  static uint8_t bob_pk[32];
  static uint8_t bob_sk[32];

  generateX25519Keypair(alice_sk, alice_pk);

  Serial.println("Alice's keys: ");
  printHexLn(alice_sk, 32);
  printHexLn(alice_pk, 32);


  generateX25519Keypair(bob_sk, bob_pk);

  uint8_t alice_res[32];
  uint8_t bob_res[32];

  combineX25519Keys(alice_sk, bob_pk, alice_res);
  combineX25519Keys(bob_sk, alice_pk, bob_res);

  Serial.print("Check that the shared secrets match ... ");
  if (memcmp(alice_res, bob_res, 32) == 0)
    Serial.println("ok");
  else
    Serial.println("failed");
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

const uint8_t* find_drone_key(uint64_t identifier) {
  for (size_t i = 0; i < kNDroneRecords; i++) {
    if (drone_records[i].identifier == identifier) {
      return drone_records[i].static_public_key;
    }
  }
  return nullptr;
}
