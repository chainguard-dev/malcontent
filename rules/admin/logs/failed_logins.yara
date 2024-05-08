
rule failed_logins : suspicious {
  meta:
    description = "accesses failed logins"
    hash_2023_FontOnLake_1829B0E34807765F2B254EA5514D7BB587AECA3F_elf = "5e9d356cdfc85a66f8fbab29bf43e95f19489c66d2a970e33d031f267298b482"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
    hash_2023_FontOnLake_8D6ACA824D1A717AE908669E356E2D4BB6F857B0_elf = "265e8236da27a35306cde4e57d73077c94c35e7a73da086273af09179f78f37a"
  strings:
    $f_wtmp = "/var/log/btmp" fullword
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho = "_PATH_RWHODIR" fullword
  condition:
    any of ($f*) and none of ($not*)
}
