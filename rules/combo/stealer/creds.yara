
rule suspected_data_stealer : high {
  meta:
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
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
