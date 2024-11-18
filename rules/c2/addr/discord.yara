rule discord: medium {
  meta:
    description = "may report back to 'Discord'"

  strings:
    $t1 = "discordapp.com"
    $t2 = "Discord"

  condition:
    any of them
}

