include "rules/global.yara"

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

rule discord_exfil: critical {
  meta:
    description = "exfiltrates data via discord webhook"

  condition:
    filesize < 100MB and discord_bot and iplookup_website
}
