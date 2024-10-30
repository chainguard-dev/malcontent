rule bot: medium {
  meta:
    description = "References a 'botnet'"

  strings:
    $bot_deployed = "bot deployed"
    $botnet       = "Botnet"

  condition:
    filesize < 20MB and any of them
}

rule botnet_high: high {
  meta:
    description = "References a 'botnet'"

  strings:
    $bot_deployed  = "bot deployed"
    $botnet        = "Botnet"
    $not_phishing  = "phishing"
    $not_keylogger = "keylogger"

  condition:
    filesize < 20MB and any of ($bot*) and none of ($not*)
}
