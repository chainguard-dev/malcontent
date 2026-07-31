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
    $not_wikiticker_contribution = "Undid revision 680586363 by"

    // These two co-occur in threat-taxonomy bundles (Kibana's security solution
    // ships the whole ATT&CK vocabulary in one chunk). On its own either word is
    // ordinary botnet functionality - a keylogging botnet says "keylogger" - so
    // the pair is required as a set rather than member-by-member.
    $notgrp_taxonomy_phishing  = "phishing"
    $notgrp_taxonomy_keylogger = "keylogger"

  condition:
    filesize < 20MB and any of ($bot*) and none of ($not_*) and not all of ($notgrp_taxonomy*)
}
