
rule powershell_hidden_short : high {
  meta:
    description = "Runs powershell with a hidden command"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
  strings:
    $ps = "powershell" ascii wide nocase
    $hidden = " -w hidden " ascii wide nocase
  condition:
    all of them
}

rule powershell_hidden_long : medium {
  meta:
    description = "Runs powershell with a hidden command"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
    hash_2023_py_guigrand_4_67_setup = "4cb4b9fcce78237f0ef025d1ffda8ca8bc79bf8d4c199e4bfc6eff84ce9ce554"
    hash_2023_py_killtoolad_3_65_setup = "64ec7b05442356293e903afe028637d821bad4444c4e1e11b73a4ff540fe480b"
  strings:
    $ps = "powershell" ascii wide nocase
    $ws = "-WindowStyle" ascii wide nocase
    $hidden = "hidden " ascii wide nocase
  condition:
    all of them
}
