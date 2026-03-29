idf_component_register(SRCS
  "app_main.c" "camera.c" "audio.c"
  INCLUDE_DIRS "."
  REQUIRES console esp_driver_uart esp_wifi esp_event esp_netif esp_timer nvs_flash esp_http_client esp_websocket_client cjson
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")
