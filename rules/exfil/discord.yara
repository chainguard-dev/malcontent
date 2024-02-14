
rule discord_bot : suspicious {
  meta:
    ref = "https://github.com/bartblaze/community/blob/3f3997f8c79c3605ae6d5324c8578cb12c452512/data/yara/binaries/indicator_suspicious.yar#L706"
  strings:
    $s1 = "discord.com/api/webhooks"
    $s2 = "cdn.discordapp.com/attachments"
  condition:
    any of them
}