#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "nvs_flash.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/dhm.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mqtt_client.h"

#define TAG "MQTT_CHAT"

#define MQTT_BROKER "broker.mqtt.cool"
#define MQTT_PORT 1883

#define AP_SSID "ESP32_Setup"
#define AP_PASS "esp32pass"
#define CAPTIVE_PASS "secret123"
#define NVS_NAMESPACE "wifi_creds"
#define STATUS_INTERVAL 30000
#define DNS_PORT 53

#define CRYPTO_TEST_MODE true
#define TEST_AES_KEY "MySecretKey1234567890123456789012" // 32 bytes for AES-256

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16
#define DH_KEY_SIZE 256

static bool wifi_connected = false;
static bool logged_in = false;
static bool captive_mode = true;
static bool mqtt_connected = false;
static uint64_t wifiReconnectTime = 0;
static char deviceID[20];

static esp_netif_t *ap_netif;
static esp_netif_t *sta_netif;
static httpd_handle_t web_server = NULL;
static struct udp_pcb *dns_pcb = NULL;
static esp_mqtt_client_handle_t mqtt_client = NULL;

// Forward declaration
static void initiateKeyExchange(void);

// Define CryptoContext struct before its use
typedef struct {
  uint8_t aes_key[AES_KEY_SIZE];
  uint8_t shared_secret[DH_KEY_SIZE];
  bool keys_established;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_dhm_context dhm;
} CryptoContext;

static CryptoContext crypto_ctx;

static const unsigned char dh_P[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
  0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
  0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
  0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
  0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
  0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
  0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
  0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
  0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
  0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
  0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
  0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
  0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
  0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
  0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
  0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
  0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char dh_G[] = { 0x02 };

static char *base64Encode(const uint8_t* data, size_t len) {
  size_t olen = 0;
  int ret = mbedtls_base64_encode(NULL, 0, &olen, data, len);
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return NULL;

  unsigned char* buf = (unsigned char*)malloc(olen + 1);
  if (!buf) return NULL;

  ret = mbedtls_base64_encode(buf, olen, &olen, data, len);
  if (ret != 0) {
    free(buf);
    return NULL;
  }

  buf[olen] = '\0';
  return (char*)buf;
}

static int base64Decode(const char* encoded, unsigned char** out_buf, size_t* out_len) {
  *out_len = 0;
  int ret = mbedtls_base64_decode(NULL, 0, out_len, (const unsigned char*)encoded, strlen(encoded));
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return ret;

  *out_buf = (unsigned char*)malloc(*out_len);
  if (!*out_buf) return -1;

  ret = mbedtls_base64_decode(*out_buf, *out_len, out_len, (const unsigned char*)encoded, strlen(encoded));
  if (ret != 0) {
    free(*out_buf);
    *out_buf = NULL;
  }
  return ret;
}

static void initCrypto() {
  ESP_LOGI(TAG, "[Crypto] Initializing cryptographic context");

  mbedtls_entropy_init(&crypto_ctx.entropy);
  mbedtls_ctr_drbg_init(&crypto_ctx.ctr_drbg);
  mbedtls_dhm_init(&crypto_ctx.dhm);

  const char *pers = "esp32_mqtt_crypto";
  int ret = mbedtls_ctr_drbg_seed(&crypto_ctx.ctr_drbg, mbedtls_entropy_func,
                                  &crypto_ctx.entropy, (const unsigned char*)pers, strlen(pers));

  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
    return;
  }

  if (CRYPTO_TEST_MODE) {
    memcpy(crypto_ctx.aes_key, TEST_AES_KEY, AES_KEY_SIZE);
    crypto_ctx.keys_established = true;
    ESP_LOGI(TAG, "[Crypto] Test mode: Using predefined AES key");
  } else {
    // Convert raw bytes to MPI format for newer mbedTLS versions
    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    
    ret = mbedtls_mpi_read_binary(&P, dh_P, sizeof(dh_P));
    if (ret != 0) {
      ESP_LOGE(TAG, "[Crypto] Error: Failed to read P parameter: -0x%04x", -ret);
      mbedtls_mpi_free(&P);
      mbedtls_mpi_free(&G);
      return;
    }
    
    ret = mbedtls_mpi_read_binary(&G, dh_G, sizeof(dh_G));
    if (ret != 0) {
      ESP_LOGE(TAG, "[Crypto] Error: Failed to read G parameter: -0x%04x", -ret);
      mbedtls_mpi_free(&P);
      mbedtls_mpi_free(&G);
      return;
    }
    
    ret = mbedtls_dhm_set_group(&crypto_ctx.dhm, &P, &G);
    if (ret != 0) {
      ESP_LOGE(TAG, "[Crypto] Error: Failed to set DH group parameters: -0x%04x", -ret);
      mbedtls_mpi_free(&P);
      mbedtls_mpi_free(&G);
      return;
    }
    
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);
    crypto_ctx.keys_established = false;
  }

  ESP_LOGI(TAG, "[Crypto] Cryptographic context initialized successfully");
}

static char *generateDHPublicKey() {
  ESP_LOGI(TAG, "[Crypto] Generating DH public key");

  unsigned char pubkey_buf[DH_KEY_SIZE];
  size_t pubkey_len = mbedtls_dhm_get_len(&crypto_ctx.dhm);
  if (pubkey_len > DH_KEY_SIZE) pubkey_len = DH_KEY_SIZE;
  int ret = mbedtls_dhm_make_public(&crypto_ctx.dhm, (int)pubkey_len,
                                  pubkey_buf, sizeof(pubkey_buf),
                                  mbedtls_ctr_drbg_random, &crypto_ctx.ctr_drbg);

  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: DH public key generation failed: -0x%04x", -ret);
    return NULL;
  }

  return base64Encode(pubkey_buf, pubkey_len);
}

static bool computeSharedSecret(const char* peer_pubkey_b64) {
  ESP_LOGI(TAG, "[Crypto] Computing shared secret");

  unsigned char* peer_pubkey = NULL;
  size_t peer_len = 0;
  if (base64Decode(peer_pubkey_b64, &peer_pubkey, &peer_len) != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: Base64 decode failed");
    return false;
  }

  if (peer_len != sizeof(dh_P)) {
    ESP_LOGE(TAG, "[Crypto] Error: Invalid peer public key length: %d", (int)peer_len);
    free(peer_pubkey);
    return false;
  }

  int ret = mbedtls_dhm_read_public(&crypto_ctx.dhm, peer_pubkey, peer_len);
  free(peer_pubkey);
  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: Failed to import peer public key: -0x%04x", -ret);
    return false;
  }

  size_t shared_len = DH_KEY_SIZE;
  ret = mbedtls_dhm_calc_secret(&crypto_ctx.dhm, crypto_ctx.shared_secret, DH_KEY_SIZE,
                                &shared_len, mbedtls_ctr_drbg_random, &crypto_ctx.ctr_drbg);

  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: Shared secret computation failed: -0x%04x", -ret);
    return false;
  }

  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  if (ret == 0) {
    mbedtls_md_hmac_starts(&md_ctx, (const unsigned char*)"ESP32_MQTT_KEY", 14);
    mbedtls_md_hmac_update(&md_ctx, crypto_ctx.shared_secret, shared_len);
    mbedtls_md_hmac_finish(&md_ctx, crypto_ctx.aes_key);
    mbedtls_md_free(&md_ctx);

    crypto_ctx.keys_established = true;
    ESP_LOGI(TAG, "[Crypto] Shared secret computed and AES key derived successfully");
    return true;
  }

  mbedtls_md_free(&md_ctx);
  ESP_LOGE(TAG, "[Crypto] Error: Key derivation failed: -0x%04x", -ret);
  return false;
}

static int encryptMessage(const char* plaintext, char** encrypted_payload) {
  *encrypted_payload = NULL;
  if (!crypto_ctx.keys_established) {
    ESP_LOGW(TAG, "[Crypto] Warning: Encryption keys not established, sending plaintext");
    *encrypted_payload = strdup(plaintext);
    return 0;
  }

  uint8_t iv[AES_IV_SIZE];
  int ret = mbedtls_ctr_drbg_random(&crypto_ctx.ctr_drbg, iv, AES_IV_SIZE);
  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: IV generation failed: -0x%04x", -ret);
    *encrypted_payload = strdup(plaintext);
    return ret;
  }

  size_t plaintext_len = strlen(plaintext);
  uint8_t* ciphertext = (uint8_t*)malloc(plaintext_len);
  if (!ciphertext) {
    ESP_LOGE(TAG, "[Crypto] Error: Memory allocation failed for encryption");
    *encrypted_payload = strdup(plaintext);
    return -1;
  }

  uint8_t tag[AES_TAG_SIZE];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, crypto_ctx.aes_key, AES_KEY_SIZE * 8);
  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: GCM setkey failed: -0x%04x", -ret);
    free(ciphertext);
    mbedtls_gcm_free(&gcm);
    *encrypted_payload = strdup(plaintext);
    return ret;
  }

  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len,
                                  iv, AES_IV_SIZE, NULL, 0,
                                  (const unsigned char*)plaintext,
                                  ciphertext, AES_TAG_SIZE, tag);
  mbedtls_gcm_free(&gcm);
  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: Encryption failed: -0x%04x", -ret);
    free(ciphertext);
    *encrypted_payload = strdup(plaintext);
    return ret;
  }

  char* iv_b64 = base64Encode(iv, AES_IV_SIZE);
  char* ciphertext_b64 = base64Encode(ciphertext, plaintext_len);
  char* tag_b64 = base64Encode(tag, AES_TAG_SIZE);
  free(ciphertext);

  if (!iv_b64 || !ciphertext_b64 || !tag_b64) {
    ESP_LOGE(TAG, "[Crypto] Error: Base64 encoding failed");
    free(iv_b64);
    free(ciphertext_b64);
    free(tag_b64);
    *encrypted_payload = strdup(plaintext);
    return -1;
  }

  size_t payload_len = strlen(iv_b64) + strlen(ciphertext_b64) + strlen(tag_b64) + strlen(deviceID) + 128;
  *encrypted_payload = (char*)malloc(payload_len);
  if (!*encrypted_payload) {
    free(iv_b64);
    free(ciphertext_b64);
    free(tag_b64);
    *encrypted_payload = strdup(plaintext);
    return -1;
  }

  snprintf(*encrypted_payload, payload_len, "{\"encrypted\":true,\"iv\":\"%s\",\"data\":\"%s\",\"tag\":\"%s\",\"device\":\"%s\"}",
           iv_b64, ciphertext_b64, tag_b64, deviceID);

  free(iv_b64);
  free(ciphertext_b64);
  free(tag_b64);

  ESP_LOGI(TAG, "[Crypto] Message encrypted (original: %d bytes, encrypted: %d bytes)", (int)plaintext_len, (int)strlen(*encrypted_payload));

  return 0;
}

static int decryptMessage(const char* encrypted_payload, char** decrypted) {
  *decrypted = NULL;
  if (!crypto_ctx.keys_established) {
    ESP_LOGW(TAG, "[Crypto] Warning: Decryption keys not established");
    *decrypted = strdup(encrypted_payload);
    return 0;
  }

  const char* enc_check = strstr(encrypted_payload, "\"encrypted\":true");
  if (!enc_check) {
    ESP_LOGI(TAG, "[Crypto] Message is not encrypted");
    *decrypted = strdup(encrypted_payload);
    return 0;
  }

  const char* iv_start = strstr(encrypted_payload, "\"iv\":\"");
  if (!iv_start) {
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  iv_start += 6;
  const char* iv_end = strchr(iv_start, '\"');
  if (!iv_end) {
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  char* iv_b64 = strndup(iv_start, iv_end - iv_start);

  const char* data_start = strstr(encrypted_payload, "\"data\":\"");
  if (!data_start) {
    free(iv_b64);
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  data_start += 8;
  const char* data_end = strchr(data_start, '\"');
  char* data_b64 = strndup(data_start, data_end - data_start);

  const char* tag_start = strstr(encrypted_payload, "\"tag\":\"");
  if (!tag_start) {
    free(iv_b64);
    free(data_b64);
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  tag_start += 7;
  const char* tag_end = strchr(tag_start, '\"');
  char* tag_b64 = strndup(tag_start, tag_end - tag_start);

  unsigned char* iv = NULL;
  size_t iv_len = 0;
  if (base64Decode(iv_b64, &iv, &iv_len) != 0 || iv_len != AES_IV_SIZE) {
    ESP_LOGE(TAG, "[Crypto] Error: Invalid IV");
    free(iv_b64);
    free(data_b64);
    free(tag_b64);
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  free(iv_b64);

  unsigned char* ciphertext = NULL;
  size_t ciphertext_len = 0;
  if (base64Decode(data_b64, &ciphertext, &ciphertext_len) != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: Invalid ciphertext");
    free(data_b64);
    free(tag_b64);
    free(iv);
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  free(data_b64);

  unsigned char* tag = NULL;
  size_t tag_len = 0;
  if (base64Decode(tag_b64, &tag, &tag_len) != 0 || tag_len != AES_TAG_SIZE) {
    ESP_LOGE(TAG, "[Crypto] Error: Invalid tag");
    free(tag_b64);
    free(iv);
    free(ciphertext);
    *decrypted = strdup(encrypted_payload);
    return -1;
  }
  free(tag_b64);

  uint8_t* plaintext = (uint8_t*)malloc(ciphertext_len + 1);
  if (!plaintext) {
    ESP_LOGE(TAG, "[Crypto] Error: Memory allocation failed for decryption");
    free(iv);
    free(ciphertext);
    free(tag);
    *decrypted = strdup(encrypted_payload);
    return -1;
  }

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, crypto_ctx.aes_key, AES_KEY_SIZE * 8);
  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: GCM setkey failed: -0x%04x", -ret);
    free(iv);
    free(ciphertext);
    free(tag);
    free(plaintext);
    *decrypted = strdup(encrypted_payload);
    return ret;
  }

  ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len,
                                 iv, AES_IV_SIZE,
                                 NULL, 0, tag, AES_TAG_SIZE,
                                 ciphertext, plaintext);
  mbedtls_gcm_free(&gcm);
  free(iv);
  free(ciphertext);
  free(tag);

  if (ret != 0) {
    ESP_LOGE(TAG, "[Crypto] Error: Decryption failed: -0x%04x", -ret);
    free(plaintext);
    *decrypted = strdup(encrypted_payload);
    return ret;
  }

  plaintext[ciphertext_len] = '\0';
  *decrypted = (char*)plaintext;

  ESP_LOGI(TAG, "[Crypto] Message decrypted successfully (%d bytes)", (int)ciphertext_len);

  return 0;
}

static esp_err_t saveWiFiCredentials(const char *ssid, const char *pass) {
  nvs_handle_t prefs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &prefs);
  if (err != ESP_OK) return err;

  err = nvs_set_str(prefs, "ssid", ssid);
  if (err == ESP_OK) err = nvs_set_str(prefs, "pass", pass);
  if (err == ESP_OK) err = nvs_commit(prefs);

  nvs_close(prefs);
  ESP_LOGI(TAG, "[NVS] WiFi credentials saved");
  return err;
}

static bool loadWiFiCredentials(char **ssid, char **pass) {
  *ssid = NULL;
  *pass = NULL;

  nvs_handle_t prefs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &prefs);
  if (err != ESP_OK) return false;

  size_t len = 0;
  err = nvs_get_str(prefs, "ssid", NULL, &len);
  if (err != ESP_OK) {
    nvs_close(prefs);
    return false;
  }

  *ssid = (char*)malloc(len);
  if (!*ssid) {
    nvs_close(prefs);
    return false;
  }
  err = nvs_get_str(prefs, "ssid", *ssid, &len);
  if (err != ESP_OK) {
    free(*ssid);
    *ssid = NULL;
    nvs_close(prefs);
    return false;
  }

  len = 0;
  err = nvs_get_str(prefs, "pass", NULL, &len);
  if (err != ESP_OK) {
    free(*ssid);
    *ssid = NULL;
    nvs_close(prefs);
    return false;
  }

  *pass = (char*)malloc(len);
  if (!*pass) {
    free(*ssid);
    *ssid = NULL;
    nvs_close(prefs);
    return false;
  }
  err = nvs_get_str(prefs, "pass", *pass, &len);
  if (err != ESP_OK) {
    free(*pass);
    *pass = NULL;
    free(*ssid);
    *ssid = NULL;
    nvs_close(prefs);
    return false;
  }

  nvs_close(prefs);
  ESP_LOGI(TAG, "[NVS] Loaded credentials - SSID: %s", *ssid);
  return true;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
  if (event_base == WIFI_EVENT) {
    switch(event_id) {
      case WIFI_EVENT_STA_START:
        ESP_LOGI(TAG, "[WiFi Event] STA Started");
        esp_wifi_connect();
        break;

      case WIFI_EVENT_STA_CONNECTED:
        ESP_LOGI(TAG, "[WiFi Event] Connected to AP");
        break;

      case WIFI_EVENT_STA_DISCONNECTED:
        ESP_LOGI(TAG, "[WiFi Event] Disconnected from WiFi");
        wifi_connected = false;
        mqtt_connected = false;
        wifiReconnectTime = esp_timer_get_time() / 1000 + 5000;
        break;

      case WIFI_EVENT_AP_START:
        ESP_LOGI(TAG, "[WiFi Event] AP Started - SSID: %s", AP_SSID);
        break;

      case WIFI_EVENT_AP_STACONNECTED:
        ESP_LOGI(TAG, "[WiFi Event] Client connected to AP");
        break;

      case WIFI_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(TAG, "[WiFi Event] Client disconnected from AP");
        break;

      default:
        break;
    }
  } else if (event_base == IP_EVENT) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
      ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
      char ip_str[16];
      esp_ip4addr_ntoa(&event->ip_info.ip, ip_str, sizeof(ip_str));
      ESP_LOGI(TAG, "[WiFi Event] Got IP: %s", ip_str);
      wifi_connected = true;
      captive_mode = false;
      if (web_server) {
        httpd_stop(web_server);
        web_server = NULL;
      }
      if (dns_pcb) {
        udp_remove(dns_pcb);
        dns_pcb = NULL;
      }
    } else if (event_id == IP_EVENT_STA_LOST_IP) {
      ESP_LOGI(TAG, "[WiFi Event] Lost IP address");
      wifi_connected = false;
      mqtt_connected = false;
    }
  }
}

static void dns_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
  if (p == NULL) return;

  if (p->len < 12) {
    pbuf_free(p);
    return;
  }

  uint8_t *data = (uint8_t*)p->payload;
  if ((data[2] & 0x80) == 0) { // Query
    uint16_t questions = (data[4] << 8) | data[5];
    if (questions == 1) {
      // Skip to question
      uint8_t *ptr = data + 12;
      while (*ptr) ptr += *ptr + 1;
      ptr++;
      uint16_t qtype = (ptr[0] << 8) | ptr[1];
      uint16_t qclass = (ptr[2] << 8) | ptr[3];

      if (qtype == 1 && qclass == 1) { // A record, IN class
        struct pbuf *r = pbuf_alloc(PBUF_TRANSPORT, p->len + 16, PBUF_RAM);
        if (r) {
          memcpy(r->payload, p->payload, p->len);

          uint8_t *rdata = (uint8_t*)r->payload;
          rdata[2] = 0x84; // Response, AA
          rdata[3] = 0x00;
          rdata[6] = 0;
          rdata[7] = 1; // 1 answer

          rdata += p->len;

          // Pointer to name
          *rdata++ = 0xc0;
          *rdata++ = 0x0c;

          *rdata++ = 0x00;
          *rdata++ = 0x01; // Type A

          *rdata++ = 0x00;
          *rdata++ = 0x01; // Class IN

          *rdata++ = 0x00;
          *rdata++ = 0x00;
          *rdata++ = 0x00;
          *rdata++ = 0x78; // TTL 120

          *rdata++ = 0x00;
          *rdata++ = 0x04; // Len 4

          esp_netif_ip_info_t ip_info;
          esp_netif_get_ip_info(ap_netif, &ip_info);

          memcpy(rdata, &ip_info.ip.addr, 4);

          r->len = p->len + 16;
          r->tot_len = r->len;

          udp_sendto(pcb, r, addr, port);
          pbuf_free(r);
        }
      }
    }
  }

  pbuf_free(p);
}

static esp_err_t handle_root(httpd_req_t *req) {
  ESP_LOGI(TAG, "[Web] Root request");

  char page_buf[2048];
  if (!logged_in) {
    snprintf(page_buf, sizeof(page_buf), "<!DOCTYPE html><html><head>"
             "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
             "<title>ESP32 Setup</title>"
             "<style>body { font-family: Arial; margin: 40px; background: #f0f0f0; }"
             ".container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 10px; }"
             "input[type='password'], input[type='text'] { width: 100%%; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; }"
             "input[type='submit'] { width: 100%%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }"
             "input[type='submit']:hover { background: #0056b3; }</style></head><body>"
             "<div class='container'><h2>Login Required</h2>"
             "<p>Enter the access password to configure WiFi settings.</p>"
             "<form method='post' action='/login'>"
             "<input type='password' name='key' placeholder='Access Password' required>"
             "<input type='submit' value='Login'></form></div></body></html>");
  } else {
    snprintf(page_buf, sizeof(page_buf), "<!DOCTYPE html><html><head>"
             "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
             "<title>WiFi Setup</title>"
             "<style>body { font-family: Arial; margin: 40px; background: #f0f0f0; }"
             ".container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 10px; }"
             "input[type='password'], input[type='text'] { width: 100%%; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; }"
             "input[type='submit'] { width: 100%%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }"
             "input[type='submit']:hover { background: #1e7e34; }"
             ".info { background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }</style></head><body>"
             "<div class='container'><h2>WiFi Configuration</h2>"
             "<div class='info'><strong>Device ID:</strong> %s<br>"
             "<strong>Current Mode:</strong> Access Point</div>"
             "<form method='post' action='/set_wifi'>"
             "<input type='text' name='ssid' placeholder='WiFi Network Name (SSID)' required>"
             "<input type='password' name='pass' placeholder='WiFi Password'>"
             "<input type='submit' value='Connect to WiFi'></form>"
             "<p><small>Device will restart after saving credentials.</small></p></div></body></html>", deviceID);
  }

  httpd_resp_send(req, page_buf, strlen(page_buf));
  return ESP_OK;
}

static esp_err_t handle_login(httpd_req_t *req) {
  char buf[256];
  if (req->content_len > sizeof(buf) - 1) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Payload too large");
    return ESP_FAIL;
  }

  int ret = httpd_req_recv(req, buf, req->content_len);
  if (ret <= 0) {
    return ESP_FAIL;
  }

  buf[ret] = '\0';

  char *key = strstr(buf, "key=");
  if (key) key += 4;

  if (key && strcmp(key, CAPTIVE_PASS) == 0) {
    logged_in = true;
    ESP_LOGI(TAG, "[Web] Login successful");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, "Login success. Redirecting...", HTTPD_RESP_USE_STRLEN);
  } else {
    ESP_LOGI(TAG, "[Web] Login failed - wrong password");
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_send(req, "<html><body><h2>Login Failed</h2><p>Wrong password!</p><a href='/'>Try Again</a></body></html>", HTTPD_RESP_USE_STRLEN);
  }

  return ESP_OK;
}

static esp_err_t handle_set_wifi(httpd_req_t *req) {
  if (!logged_in) {
    httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Access Denied");
    return ESP_FAIL;
  }

  char buf[256];
  if (req->content_len > sizeof(buf) - 1) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Payload too large");
    return ESP_FAIL;
  }

  int ret = httpd_req_recv(req, buf, req->content_len);
  if (ret <= 0) {
    return ESP_FAIL;
  }

  buf[ret] = '\0';

if (strlen(buf) > 200) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Input too long");
    return ESP_FAIL;
}

  char *ssid_start = strstr(buf, "ssid=");
  if (!ssid_start) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid data");
    return ESP_FAIL;
  }
  ssid_start += 5;

  char *pass_start = strstr(ssid_start, "&pass=");
  char ssid[33] = {0};
if (pass_start) {
    if (pass_start - ssid_start > 32) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID too long");
        return ESP_FAIL;
    }
    strncpy(ssid, ssid_start, pass_start - ssid_start);
    ssid[pass_start - ssid_start] = '\0';
    pass_start += 6;
} else {
    if (strlen(ssid_start) > 32) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID too long");
        return ESP_FAIL;
    }
    strncpy(ssid, ssid_start, sizeof(ssid) - 1);
    ssid[32] = '\0';
    pass_start = "";
}

  char pass[65] = {0};
if (strlen(pass_start) > 63) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password too long");
    return ESP_FAIL;
}
strncpy(pass, pass_start, sizeof(pass) - 1);

  ESP_LOGI(TAG, "[Web] Received WiFi credentials - SSID: %s", ssid);

  saveWiFiCredentials(ssid, pass);

  httpd_resp_send(req, "<html><body><h2>Settings Saved</h2><p>WiFi credentials saved successfully!</p><p>Device is restarting...</p></body></html>", HTTPD_RESP_USE_STRLEN);

  vTaskDelay(3000 / portTICK_PERIOD_MS);
  esp_restart();

  return ESP_OK;
}

static esp_err_t handle_not_found(httpd_req_t *req, httpd_err_code_t err) {
  ESP_LOGI(TAG, "[Web] Redirecting to captive portal");
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "/");
  httpd_resp_send(req, "Redirecting to setup page...", HTTPD_RESP_USE_STRLEN);
  return ESP_OK;
}

static void startCaptivePortal() {
  ESP_LOGI(TAG, "[Captive] Starting captive portal mode");

  esp_wifi_set_mode(WIFI_MODE_AP);
  wifi_config_t ap_config = {
    .ap = {
      .ssid = AP_SSID,
      .ssid_len = strlen(AP_SSID),
      .channel = 1,
      .password = AP_PASS,
      .max_connection = 4,
      .authmode = WIFI_AUTH_WPA2_PSK
    }
  };
  esp_wifi_set_config(WIFI_IF_AP, &ap_config);
  esp_wifi_start();

  // Start DNS
  dns_pcb = udp_new();
  if (dns_pcb) {
    ip_addr_t any_addr = IPADDR_ANY_TYPE_INIT;
    udp_bind(dns_pcb, &any_addr, DNS_PORT);
    udp_recv(dns_pcb, dns_recv, NULL);
    ESP_LOGI(TAG, "[Captive] DNS server started on port %d", DNS_PORT);
  }

  // Start HTTP server
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.uri_match_fn = httpd_uri_match_wildcard;
  config.stack_size = 8192;
  config.server_port = 80;
  config.ctrl_port = 32768;

  if (httpd_start(&web_server, &config) == ESP_OK) {
    httpd_uri_t root = {
      .uri = "/",
      .method = HTTP_GET,
      .handler = handle_root
    };
    httpd_register_uri_handler(web_server, &root);

    httpd_uri_t login = {
      .uri = "/login",
      .method = HTTP_POST,
      .handler = handle_login
    };
    httpd_register_uri_handler(web_server, &login);

    httpd_uri_t set_wifi = {
      .uri = "/set_wifi",
      .method = HTTP_POST,
      .handler = handle_set_wifi
    };
    httpd_register_uri_handler(web_server, &set_wifi);

    httpd_register_err_handler(web_server, HTTPD_404_NOT_FOUND, handle_not_found);
  }

  captive_mode = true;
  logged_in = false;
  ESP_LOGI(TAG, "[Captive] Web server started - Connect to WiFi and visit http://192.168.4.1");
}

static void connectWiFi() {
  char *ssid = NULL;
  char *pass = NULL;
  if (loadWiFiCredentials(&ssid, &pass)) {
    ESP_LOGI(TAG, "[WiFi] Attempting connection to '%s'", ssid);

    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_config_t sta_config = {
      .sta = {
        .threshold = { .authmode = WIFI_AUTH_WPA2_PSK },
        .pmf_cfg = { .capable = true, .required = false }
      }
    };
    strncpy((char*)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid));
    strncpy((char*)sta_config.sta.password, pass, sizeof(sta_config.sta.password));
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_start();

    free(ssid);
    free(pass);

    int timeout = 150; 
    while (!wifi_connected && timeout > 0) {
      vTaskDelay(100 / portTICK_PERIOD_MS);
      timeout--;
    }
    if (!wifi_connected) {
      ESP_LOGI(TAG, "[WiFi] Connection failed, starting captive portal");
      startCaptivePortal();
    }
  } else {
    ESP_LOGI(TAG, "[WiFi] No saved credentials found, starting captive portal");
    startCaptivePortal();
  }
}
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
  esp_mqtt_event_handle_t event = event_data;

  switch (event->event_id) {
    case MQTT_EVENT_CONNECTED:
      ESP_LOGI(TAG, "[MQTT] Connected");
      mqtt_connected = true;

      esp_mqtt_client_subscribe(mqtt_client, "chat/room1", 1);
      esp_mqtt_client_subscribe(mqtt_client, "chat/status", 1);
      esp_mqtt_client_subscribe(mqtt_client, "chat/keyexchange", 1);
      esp_mqtt_client_subscribe(mqtt_client, "chat/input", 1);  // NEW: Subscribe to input topic

      // Publish online status
      esp_netif_ip_info_t ip_info;
      esp_netif_get_ip_info(sta_netif, &ip_info);
      char ip_str[16];
      esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));

      char onlineMsg[256];
      snprintf(onlineMsg, sizeof(onlineMsg), "{\"device\":\"%s\",\"status\":\"online\",\"ip\":\"%s\"}", deviceID, ip_str);

      char *encrypted = NULL;
      encryptMessage(onlineMsg, &encrypted);
      esp_mqtt_client_publish(mqtt_client, "chat/status", encrypted, 0, 1, true);
      free(encrypted);

      initiateKeyExchange();
      break;

    case MQTT_EVENT_DISCONNECTED:
      ESP_LOGI(TAG, "[MQTT] Disconnected");
      mqtt_connected = false;
      break;

    case MQTT_EVENT_DATA:
      {
        char msg[event->data_len + 1];
        memcpy(msg, event->data, event->data_len);
        msg[event->data_len] = '\0';

        char topic[event->topic_len + 1];
        memcpy(topic, event->topic, event->topic_len);
        topic[event->topic_len] = '\0';

        ESP_LOGI(TAG, "[MQTT Event] Message received on topic '%s': %s", topic, msg);

        if (strcmp(topic, "chat/keyexchange") == 0) {
          const char* device_start = strstr(msg, "\"device\":\"");
          if (device_start) {
            device_start += 10;
            const char* device_end = strchr(device_start, '\"');
            if (!device_end || device_end - device_start >= 20) break;
            char peer_device[20] = {0};
            strncpy(peer_device, device_start, device_end - device_start);
            peer_device[device_end - device_start] = '\0';
            if (strcmp(peer_device, deviceID) == 0) break;
          }

          const char* pub_start = strstr(msg, "\"pubkey\":\"");
          if (pub_start) {
            pub_start += 10;
            const char* pub_end = strchr(pub_start, '\"');
            if (!pub_end || pub_end - pub_start > 512) break;
            char *peer_pubkey_b64 = strndup(pub_start, pub_end - pub_start);
            computeSharedSecret(peer_pubkey_b64);
            free(peer_pubkey_b64);
          }
        } 
        else if (strcmp(topic, "chat/input") == 0) {
          // NEW: Handle plaintext input messages - encrypt and relay them
          ESP_LOGI(TAG, "[MQTT] Received plaintext message for encryption: %s", msg);
          
          // Create formatted message with device info
          int rssi;
          esp_wifi_sta_get_rssi(&rssi);
          
          char formatted_msg[512];
          snprintf(formatted_msg, sizeof(formatted_msg), 
                  "{\"device\":\"%s\",\"message\":\"%s\",\"rssi\":%d,\"timestamp\":%llu,\"type\":\"user_message\"}", 
                  deviceID, msg, rssi, esp_timer_get_time() / 1000);
          
          // Encrypt and publish to chat/room1
          char *encrypted = NULL;
          encryptMessage(formatted_msg, &encrypted);
          if (encrypted) {
            ESP_LOGI(TAG, "[MQTT] Relaying encrypted message to chat/room1");
            esp_mqtt_client_publish(mqtt_client, "chat/room1", encrypted, 0, 1, false);
            
            // NEW: Also publish the original plaintext to input_processed for debugging
            char debug_msg[1024];
            snprintf(debug_msg, sizeof(debug_msg), 
                    "[PROCESSED by %s] Original: %s | Formatted: %s", 
                    deviceID, msg, formatted_msg);
            esp_mqtt_client_publish(mqtt_client, "chat/input_processed", debug_msg, 0, 0, false);
            ESP_LOGI(TAG, "[MQTT] Published processing info to chat/input_processed");
            
            free(encrypted);
          }
        }
        else {
          // Handle encrypted messages from chat/room1, chat/status, etc.
          char *decrypted = NULL;
          decryptMessage(msg, &decrypted);
          ESP_LOGI(TAG, "[MQTT Event] Decrypted message on %s: %s", topic, decrypted);
          
          // NEW: Publish decrypted message to debug room for monitoring
          if (strcmp(topic, "chat/room1") == 0) {
            // Publish to decrypted room for debugging
            char debug_msg[1024];
            snprintf(debug_msg, sizeof(debug_msg), 
                    "[DECRYPTED by %s] %s", deviceID, decrypted);
            esp_mqtt_client_publish(mqtt_client, "chat/room1_decrypted", debug_msg, 0, 0, false);
            ESP_LOGI(TAG, "[MQTT] Published decrypted message to chat/room1_decrypted");
          }
          else if (strcmp(topic, "chat/status") == 0) {
            // Publish status decryptions to separate debug room
            char debug_msg[1024];
            snprintf(debug_msg, sizeof(debug_msg), 
                    "[STATUS DECRYPTED by %s] %s", deviceID, decrypted);
            esp_mqtt_client_publish(mqtt_client, "chat/status_decrypted", debug_msg, 0, 0, false);
            ESP_LOGI(TAG, "[MQTT] Published decrypted status to chat/status_decrypted");
          }
          
          free(decrypted);
        }
      }
      break;

    // Add these cases to handle the missing MQTT events (to fix warnings)
    case MQTT_EVENT_ERROR:
    case MQTT_EVENT_SUBSCRIBED:
    case MQTT_EVENT_UNSUBSCRIBED:
    case MQTT_EVENT_PUBLISHED:
    case MQTT_EVENT_BEFORE_CONNECT:
    case MQTT_EVENT_DELETED:
    case MQTT_USER_EVENT:
    case MQTT_EVENT_ANY:
    default:
      break;
  }
} // <-- This closing brace was missing!
static void initiateKeyExchange() {
  ESP_LOGI(TAG, "[MQTT] Initiating Diffie-Hellman key exchange");

  char *public_key = generateDHPublicKey();
  if (!public_key) return;

  char key_exchange_msg[2048];
  snprintf(key_exchange_msg, sizeof(key_exchange_msg), "{\"device\":\"%s\",\"pubkey\":\"%s\",\"timestamp\":%llu}", deviceID, public_key, esp_timer_get_time() / 1000);
  free(public_key);

  esp_mqtt_client_publish(mqtt_client, "chat/keyexchange", key_exchange_msg, 0, 0, false);
}

static void mqttPublishMessage(const char* message) {
  if (!mqtt_connected) return;

  int rssi;
  esp_wifi_sta_get_rssi(&rssi);

  char plaintext_payload[512];
  snprintf(plaintext_payload, sizeof(plaintext_payload), "{\"device\":\"%s\",\"message\":\"%s\",\"rssi\":%d,\"timestamp\":%llu}", deviceID, message, rssi, esp_timer_get_time() / 1000);

  char *encrypted = NULL;
  encryptMessage(plaintext_payload, &encrypted);
  if (encrypted) {
    esp_mqtt_client_publish(mqtt_client, "chat/room1", encrypted, 0, 1, false);
    free(encrypted);
  }
}

static void mqttPublishStatus(const char* status) {
  if (!mqtt_connected) return;

  int rssi;
  esp_wifi_sta_get_rssi(&rssi);

  char plaintext_payload[512];
  snprintf(plaintext_payload, sizeof(plaintext_payload), "{\"device\":\"%s\",\"status\":\"%s\",\"rssi\":%d,\"uptime\":%llu,\"free_heap\":%d,\"encryption_active\":%d}",
           deviceID, status, rssi, esp_timer_get_time() / 1000, (int)esp_get_free_heap_size(), crypto_ctx.keys_established ? 1 : 0);

  char *encrypted = NULL;
  encryptMessage(plaintext_payload, &encrypted);
  if (encrypted) {
    esp_mqtt_client_publish(mqtt_client, "chat/status", encrypted, 0, 1, true);
    free(encrypted);
  }
}

static void chatTask(void* param) {
  while (1) {
    if (mqtt_connected) {
      mqttPublishMessage("Hello from ESP32!");
    }
    vTaskDelay(15000 / portTICK_PERIOD_MS);
  }
}

static void statusTask(void* param) {
  while (1) {
    if (wifi_connected && mqtt_connected) {
      mqttPublishStatus("online");
    }
    vTaskDelay(STATUS_INTERVAL / portTICK_PERIOD_MS);
  }
}

static void management_task(void* param) {
  while (1) {
    if (!captive_mode && !wifi_connected && wifiReconnectTime > 0 && esp_timer_get_time() / 1000 > wifiReconnectTime) {
      ESP_LOGI(TAG, "[Management] Attempting WiFi reconnection...");
      connectWiFi();
      wifiReconnectTime = 0;
    }
    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
}

void app_main(void) {
  ESP_LOGI(TAG, "\n=== ESP32 Captive Portal MQTT Chat with AES-256 Encryption ===");

  uint8_t mac[6];
  esp_efuse_mac_get_default(mac);
  snprintf(deviceID, sizeof(deviceID), "ESP32-%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  ESP_LOGI(TAG, "[Setup] Device ID: %s", deviceID);

  initCrypto();

  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }

  esp_netif_init();
  esp_event_loop_create_default();
  ap_netif = esp_netif_create_default_wifi_ap();
  sta_netif = esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);

  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
  esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);

  char will_msg[128];
  snprintf(will_msg, sizeof(will_msg), "{\"device\":\"%s\",\"status\":\"offline\"}", deviceID);

  esp_mqtt_client_config_t mqtt_cfg = {
    .broker.address.uri = "mqtt://" MQTT_BROKER,
    .credentials.client_id = deviceID,
    .session.last_will = {
      .topic = "chat/status",
      .msg = will_msg,
      .msg_len = 0, // null-terminated
      .qos = 1,
      .retain = true
    },
    .network.reconnect_timeout_ms = 5000,
    .buffer.size = 2048
  };

  mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
  esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
  esp_mqtt_client_start(mqtt_client);

  connectWiFi();

  xTaskCreate(chatTask, "chatTask", 8192, NULL, 1, NULL);
  xTaskCreate(statusTask, "statusTask", 4096, NULL, 1, NULL);
  xTaskCreate(management_task, "managementTask", 4096, NULL, 1, NULL);

  ESP_LOGI(TAG, "[Setup] Setup completed");
}