rule stealer: high {
  meta:
    description = "literally calls itself a stealer"

  strings:
    $Stealer     = "Stealer" fullword
    $Stealer2    = "stealer" fullword
    $StealToken  = "stealToken"
    $StealToken2 = "StealTokens"

    $o_requests = "requests" fullword
    $o_telegram = "Telegram" fullword
    $o_cookies  = "Cookies" fullword
    $o_Password = "Password" fullword
    $o_roblox   = "Roblox" fullword
    $o_Discord  = "Discord" fullword
    $o_Steam    = "Steam" fullword
    $o_riot     = "Riot Games" fullword

  condition:
    filesize < 128KB and any of ($Steal*) and any of ($o*)
}
