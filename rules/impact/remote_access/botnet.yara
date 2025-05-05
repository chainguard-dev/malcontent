rule bot: medium {
  meta:
    description = "References a 'bot'"

  strings:
    $BOTDIR = "BOTDIR"
    $botdir = "botdir"

  condition:
    filesize < 1MB and any of them
}

rule bot_id: medium {
  meta:
    description = "References a 'bot_id'"

  strings:
    $BOT_ID = "BOT_ID"
    $bot_id = "bot_id"
    $BotId  = "BotId"

  condition:
    filesize < 1MB and any of them
}

rule botnet_high: high {
  meta:
    description = "References a 'botnet'"

  strings:
    $bot_deployed                = "bot deployed"
    $botnet                      = "Botnet"
    $not_phishing                = "phishing"
    $not_keylogger               = "keylogger"
    $not_wikiticker_contribution = "Undid revision 680586363 by"

  condition:
    filesize < 20MB and any of ($bot*) and none of ($not*)
}
