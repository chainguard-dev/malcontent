rule chromium_master_password: critical {
  meta:
    description                          = "Gets Chromium credit card information"
    hash_2018_CookieMiner_nonelittlecode = "7bc657c96c15ec0629740e00a9c7497417b599694c6b7598eeff095136cbd507"
    hash_2024_2024_GitHub_Clipper_main   = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
    hash_2024_2024_GitHub_Clipper_main   = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"

  strings:
    $web_data      = "Web Data"
    $encrypted_key = "credit_cards"
    $c             = "Chrome"
    $c2            = "Chromium"
    $not_chromium  = "CHROMIUM_TIMESTAMP"

  condition:
    filesize < 25MB and any of ($c*) and $web_data and $encrypted_key and none of ($not*)
}
