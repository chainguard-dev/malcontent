
rule discord_bot : suspicious {
  meta:
    description = "Uses the Discord webhooks API"
    ref = "https://github.com/bartblaze/community/blob/3f3997f8c79c3605ae6d5324c8578cb12c452512/data/yara/binaries/indicator_suspicious.yar#L706"
    hash_2023_pan_chan_6896 = "6896b02503c15ffa68e17404f1c97fd53ea7b53c336a7b8b34e7767f156a9cf2"
    hash_2023_pan_chan_73ed = "73ed0b692fda696efd5f8e33dc05210e54b17e4e4a39183c8462bcc5a3ba06cc"
    hash_2023_pan_chan_99ed = "99ed2445553e490c912ee8493073cc4340e7c6310b0b7fc425ffe8340c551473"
  strings:
    $s1 = "discord.com/api/webhooks"
  condition:
    any of them
}
