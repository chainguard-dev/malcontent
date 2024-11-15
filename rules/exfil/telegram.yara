rule telegram_bot: high {
  meta:
    ref = "https://github.com/bartblaze/community/blob/3f3997f8c79c3605ae6d5324c8578cb12c452512/data/yara/binaries/indicator_high.yar#L676"

  strings:
    $s1     = "api.telegram.org"
    $s1_b64 = "api.telegram.org" base64
    $s3     = "Content-Disposition: form-data; name=\""
    $p1     = "/sendMessage"
    $p1_b64 = "/sendMessage" base64
    $p2     = "/sendDocument"
    $p4     = "/sendLocation"

  condition:
    2 of ($s*) or (2 of ($p*) and 1 of ($s*))
}
