
rule suspected_data_stealer : suspicious {
  strings:
    $e_atomic = "Atomic" fullword
    $e_bitcoin = "Bitcoin" fullword
    $e_chromium = "Chromium"
    $e_chrome = "Chrome" fullword
    $e_firefox = "Firefox"
    $e_openvpn = "OpenVPN"
    $s_bookmarks = "Bookmarks"
    $s_history = "History"
    $s_binance = "Binance"
    $s_discord = "Discord"
    $s_electrum = "Electrum"
    $s_electrum2 = "/.elect"
    $s_exodus = "Exodus"
    $s_obs = "obs-studio"
    $s_pidgin = "Pidgin"
    $s_snowflake = "Snowflake"
    $s_telegram = "Telegram"
    $s_zcash = "Zcash"
    $s_zip = "zip -r"
    $s_login = "Login Data"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_chromium = "RasterCHROMIUM"
    $not_descriptive = "Binance Pay is a contactless"
  condition:
    (8 of them and none of ($not*)) or 5 of ($s*)
}
