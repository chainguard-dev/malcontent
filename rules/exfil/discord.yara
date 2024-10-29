
rule discord_bot : high {
  meta:
    description = "Uses the Discord webhooks API"
    ref = "https://github.com/bartblaze/community/blob/3f3997f8c79c3605ae6d5324c8578cb12c452512/data/yara/binaries/indicator_high.yar#L706"
    hash_2023_pan_chan_6896 = "6896b02503c15ffa68e17404f1c97fd53ea7b53c336a7b8b34e7767f156a9cf2"
    hash_2023_pan_chan_73ed = "73ed0b692fda696efd5f8e33dc05210e54b17e4e4a39183c8462bcc5a3ba06cc"
    hash_2023_pan_chan_99ed = "99ed2445553e490c912ee8493073cc4340e7c6310b0b7fc425ffe8340c551473"
  strings:
	$ = /discordapp.com\/api\/webhooks[\/\d]{0,32}/
	$ = /discord.com\/api\/webhooks[\/\d]{0,32}/
	$ = "import discord"
  condition:
    any of them
}

private rule iplookup_website_value_copy : high {
  meta:
    description = "public service to discover external IP address"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
    hash_2023_Unix_Trojan_Ipstorm_1996 = "1996927b41960a2af8e49cf745ed6668bc5b8d7855c2bb116f98104163e29000"
    hash_2023_Unix_Trojan_Ipstorm_2f6f = "2f6f44e3e2baf701ae1ee3826986f89df4e5314c8ba50615fb6580f1ef54c830"
  strings:
    $ipify = "ipify.org"
    $wtfismyip = "wtfismyip"
    $iplogger = "iplogger.org"
    $getjsonip = "getjsonip"
    $ipconfig_me = "ifconfig.me"
    $icanhazip = "icanhazip"
    $ident_me = "ident.me" fullword
    $showip_net = "showip.net" fullword
    $ifconfig_io = "ifconfig.io" fullword
    $ifconfig_co = "ifconfig.co" fullword
    $ipinfo = "ipinfo.io"
    $ipify_b = "ipify.org" base64
    $wtfismyip_b = "wtfismyip" base64
    $iplogger_b = "iplogger.org" base64
    $getjsonip_b = "getjsonip" base64
    $ipinfo_b = "ipinfo.io" base64
    $ipify_x = "ipify.org" xor(1-255)
    $wtfismyip_x = "wtfismyip" xor(1-255)
    $iplogger_x = "iplogger.org" xor(1-255)
    $getjsonip_x = "getjsonip" xor(1-255)
    $ipinfo_x = "ipinfo.io" xor(1-255)
  condition:
    any of them
}


rule discord_exfil : critical {
	meta:
		description = "exfiltrates data via discord webhook"
	condition:
		filesize < 100MB and discord_bot and iplookup_website_value_copy
}