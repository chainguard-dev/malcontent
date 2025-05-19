rule keylogger_discord_telegram: high {
  meta:
    description = "likely exfiltrates keyboard events"

  strings:
    $http_Discord  = "Discord"
    $http_Telegram = "Telegram"
    $http_discord  = "Discord"
    $http_telegram = "Telegram"
    $k_keylogger   = "keylogger"
    $k_Keylogger   = "Keylogger"

  condition:
    filesize < 256KB and any of ($http*) and any of ($k*)
}

rule py_keylogger_pynput_exfil: high {
  meta:
    description = "listens for keyboard events and exfiltrates them"
    filetypes   = "py"

  strings:
    $http           = "http"
    $http_POST      = /POST[ \/\w]{0,32}/
    $http_Discord   = "Discord"
    $http_Telegram  = "Telegram"
    $http_keylogger = /[kK]eylogger/
    $f_pynput       = "pynput.keyboard"
    $f_key          = "Key" fullword
    $f_listener     = "Listener" fullword

  condition:
    filesize < 256KB and any of ($http*) and all of ($f*)
}

rule py_keykeyboard_exfil: high {
  meta:
    description = "listens for keyboard events and exfiltrates them"
    filetypes   = "py"

  strings:
    $http           = "http"
    $http_POST      = /POST[ \/\w]{0,32}/
    $http_Discord   = "Discord"
    $http_keylogger = /[kK]eylogger/
    $http_Telegram  = "Telegram"
    $f_pynput       = "pynput" fullword
    $f_keyboard     = "keyboard" fullword
    $f_key          = ".name"
    $f_listener     = "on_release"

  condition:
    filesize < 256KB and any of ($http*) and all of ($f*)
}

rule java_keylogger {
  meta:
    description = "listens for keyboard events"
    filetypes   = "jar,java"

  strings:
    $jnativehook    = "jnativehook"
    $NativeKeyEvent = "NativeKeyEvent"

  condition:
    filesize < 2MB and all of them
}
