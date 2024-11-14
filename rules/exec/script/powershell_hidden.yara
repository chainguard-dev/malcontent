rule powershell_hidden_short: high windows {
  meta:
    description = "Runs powershell with a hidden command"

  strings:
    $ps     = "powershell" ascii wide nocase
    $hidden = " -w hidden " ascii wide nocase

  condition:
    all of them
}

rule powershell_hidden_long: medium windows {
  meta:
    description = "Runs powershell with a hidden command"

  strings:
    $ps     = "powershell" ascii wide nocase
    $ws     = "-WindowStyle" ascii wide nocase
    $hidden = "hidden " ascii wide nocase

  condition:
    all of them
}
