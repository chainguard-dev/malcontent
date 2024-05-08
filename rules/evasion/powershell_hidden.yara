
rule powershell_hidden_short : suspicious {
  meta:
    description = "Runs powershell with a hidden command"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
  strings:
    $ps = "powershell" ascii wide nocase
    $hidden = " -w hidden " ascii wide nocase
  condition:
    all of them
}

rule powershell_hidden_long : notable {
  meta:
    description = "Runs powershell with a hidden command"
  strings:
    $ps = "powershell" ascii wide nocase
    $ws = "-WindowStyle" ascii wide nocase
    $hidden = "hidden " ascii wide nocase
  condition:
    all of them
}
