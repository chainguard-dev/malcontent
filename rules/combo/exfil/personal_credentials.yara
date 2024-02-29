rule suspected_data_stealer : suspicious {
  meta:
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $e_atomic = "Atomic"
    $e_bitcoin = "Bitcoin"
    $e_chromium = "Chromium"
    $e_chrome = "Chrome"
    $e_firefox = "Firefox"
    $e_openvpn = "OpenVPN"
    $s_bookmarks = "Bookmarks"
    $s_history = "History"
    $s_cookies = "Cookies"
    $s_binance = "Binance"
    $s_discord = "Discord"
    $s_electrum = "Electrum"
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
