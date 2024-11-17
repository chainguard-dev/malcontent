rule chromium_credit_cards: critical {
  meta:
    description = "Gets Chromium credit card information"

  strings:
    $web_data      = "Web Data"
    $encrypted_key = "credit_cards"
    $c             = "Chrome"
    $c2            = "Chromium"
    $not_chromium  = "CHROMIUM_TIMESTAMP"

  condition:
    filesize < 25MB and any of ($c*) and $web_data and $encrypted_key and none of ($not*)
}
