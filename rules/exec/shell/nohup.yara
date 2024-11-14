rule nohup_reference_value: medium {
  meta:
    description = "Runs command that is protected from termination"

  strings:
    $nohup         = "nohup" fullword
    $nohup_re_val  = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append    = "appending output"
    $not_usage     = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd     = "pushd"

  condition:
    filesize < 52428800 and any of ($nohup*) and none of ($not*)
}

rule elf_nohup: high {
  meta:
    description           = "Runs command that is protected from termination"
    hash_2023_Merlin_48a7 = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"

  strings:
    $nohup         = "nohup" fullword
    $nohup_re_val  = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append    = "appending output"
    $not_usage     = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd     = "pushd"

  condition:
    uint32(0) == 1179403647 and filesize < 1MB and any of ($nohup*) and none of ($not*)
}

rule nohup_bash: high {
  meta:
    description                      = "Calls bash with nohup"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"

  strings:
    $ref = /nohup bash[ \w\/\&\.\-\%\>]{0,32}/

  condition:
    any of them
}
