idf_component_register(
    SRCS "dcn.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_event nvs_flash esp_http_server lwip mbedtls mqtt
    PRIV_REQUIRES efuse
)