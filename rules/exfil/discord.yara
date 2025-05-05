rule discord_bot: high {
  meta:
    description = "Uses the Discord webhooks API"

  strings:
    $webhook_endpoint  = /discordapp.com\/api\/webhooks[\/\d]{0,32}/
    $webhook_endpoint2 = /discord.com\/api\/webhooks[\/\d]{0,32}/
    $l_discordjs       = "discord.js"
    $l_discord4j       = "discord4j"
    $l_discordgo       = "discordgo"
    $l_discord         = "import discord"
    $l_disnake         = "import disnake"
    $l_hikari          = "import hikari"
    $l_interactions    = "import interactions"
    $l_nextcord        = "import nextcord"
    $l_jda             = "net.dv8tion:JDA"
    $l_discordia       = "discordia"
    $l_eris            = /require\(("|')eris("|')\);/
    $l_oceanic         = /require\(("|')oceanic.js("|')\);/
    $l_discordphp      = "use Discord\\Discord;"

    $not_pypi_index  = /\"index_date\":\"\d{4}-\d{2}\d{2}\"/
    $not_pypi_index2 = "\"package_names\""

  condition:
    any of them and none of ($not*)
}

private rule iplookup_website_value_copy: high {
  meta:
    description = "public service to discover external IP address"

  strings:
    $ipify       = "ipify.org"
    $wtfismyip   = "wtfismyip"
    $iplogger    = "iplogger.org"
    $getjsonip   = "getjsonip"
    $ipconfig_me = "ifconfig.me"
    $icanhazip   = "icanhazip"
    $ident_me    = "ident.me" fullword
    $showip_net  = "showip.net" fullword
    $ifconfig_io = "ifconfig.io" fullword
    $ifconfig_co = "ifconfig.co" fullword
    $ipinfo      = "ipinfo.io"
    $ipify_b     = "ipify.org" base64
    $wtfismyip_b = "wtfismyip" base64
    $iplogger_b  = "iplogger.org" base64
    $getjsonip_b = "getjsonip" base64
    $ipinfo_b    = "ipinfo.io" base64
    $ipify_x     = "ipify.org" xor(1-255)
    $wtfismyip_x = "wtfismyip" xor(1-255)
    $iplogger_x  = "iplogger.org" xor(1-255)
    $getjsonip_x = "getjsonip" xor(1-255)
    $ipinfo_x    = "ipinfo.io" xor(1-255)

  condition:
    any of them
}

rule discord_exfil: critical {
  meta:
    description = "exfiltrates data via discord webhook"

  condition:
    filesize < 100MB and discord_bot and iplookup_website_value_copy
}
