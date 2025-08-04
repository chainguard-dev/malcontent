rule suspected_data_stealer: high {
  meta:
    description = "suspected data stealer"

  strings:
    $e_atomic           = "Atomic" fullword
    $e_bitcoin          = "Bitcoin" fullword
    $e_chromium         = "Chromium"
    $e_chrome           = "Chrome" fullword
    $e_firefox          = "Firefox"
    $e_openvpn          = "OpenVPN"
    $s_bookmarks        = "Bookmarks"
    $s_history          = "History"
    $s_binance          = "Binance"
    $s_discord          = "Discord"
    $s_electrum         = "Electrum"
    $s_electrum2        = "/.elect"
    $s_exodus           = "Exodus"
    $s_exodus_ext       = "aholpfdial"
    $s_crypto           = "cfgodnhcel"
    $s_obs              = "obs-studio"
    $s_pidgin           = "Pidgin"
    $s_snowflake        = "Snowflake"
    $s_telegram         = "Telegram"
    $s_zcash            = "Zcash"
    $s_zip              = "zip -r"
    $s_login            = "Login Data"
    $not_chromium       = "RasterCHROMIUM"
    $not_descriptive    = "Binance Pay is a contactless"
    $not_electron       = "ELECTRON_RUN_AS_NODE"
    $not_gpt_tokenizer1 = "GPTTokenizer"
    $not_gpt_tokenizer2 = "GPT-4"
    $not_gpt_tokenizer3 = "const bpe = c0.concat();"
    $not_gpt_tokenizer4 = "const bpe = c0.concat(c1);"
    $not_gpt_tokenizer5 = "export default bpe;"

  condition:
    (8 of them or 5 of ($s*)) and none of ($not*)
}

rule steal_creds: high {
  meta:
    description = "may steal credentials"

  strings:
    $StealCreds        = "StealCreds"
    $StealCredentials  = "StealCredentials"
    $steal_credentials = "steal_credentials"
    $steal_creds       = "steal_creds" fullword

  condition:
    any of them
}

rule previewers_alike: high {
  meta:
    description = "uploads, accesses a keychain, uses ZIP files"

  strings:
    $upload   = "upload"
    $zip      = "zip"
    $keychain = "keychain_item"

  condition:
    all of them
}

rule STRRat_high: high {
  meta:
    description = "steals multiple types of passwords"

  strings:
    $p_pass         = "pass"
    $p_keylogger    = "keylogger"
    $browser_chrome = "chrome" fullword
    $browser_ie     = "ie" fullword
    $mail_foxmail   = "foxmail"
    $mail_outlook   = "outlook"

  condition:
    filesize < 128KB and any of ($p*) and any of ($browser*) and any of ($mail*)
}

rule STRRat_critical: critical {
  meta:
    description = "steals multiple types of passwords"

  strings:
    $p_pass         = "pass"
    $p_keylogger    = "keylogger"
    $browser_chrome = "chrome" fullword
    $browser_ie     = "ie" fullword
    $mail_foxmail   = "foxmail"
    $mail_outlook   = "outlook"

  condition:
    filesize < 128KB and all of ($p*) and any of ($browser*) and any of ($mail*)
}
