rule telegram: medium {
  meta:
    discription = "may report back to 'Telegram'"

  strings:
    $t1 = "telegram.org"
    $t2 = "Telegram"

  condition:
    any of them
}

