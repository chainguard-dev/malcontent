
rule nohup_reference_value : notable {
  meta:
    description = "Runs command that is protected from termination"
  strings:
    $nohup = "nohup" fullword
    $nohup_re_val = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append = "appending output"
    $not_usage = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd = "pushd"
    $bin_sh = "#!/bin/sh"
    $bin_bash = "#!/bin/bash"
  condition:
    filesize < 52428800 and any of ($nohup*) and none of ($not*) and not $bin_sh in (0..2) and not $bin_bash in (0..2)
}

rule elf_nohup : suspicious {
  meta:
    description = "Runs command that is protected from termination"
    hash_2023_Merlin_48a7 = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Malware_Agent_b79a = "b79af4e394cbc8c19fc9b5410fa69b10325fd23f58bec330954caae135239a1f"
  strings:
    $nohup = "nohup" fullword
    $nohup_re_val = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append = "appending output"
    $not_usage = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd = "pushd"
  condition:
    uint32(0) == 1179403647 and any of ($nohup*) and none of ($not*)
}

rule trap_1 : suspicious {
  meta:
    description = "Protects itself from early termination via SIGHUP"
  strings:
    $ref = "trap '' 1"
    $ref2 = "trap \"\" 1"
  condition:
    any of them
}

rule nohup_bash : suspicious {
  meta:
    description = "Calls bash with nohup"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Malware_Agent_b79a = "b79af4e394cbc8c19fc9b5410fa69b10325fd23f58bec330954caae135239a1f"
  strings:
    $ref = /nohup bash[ \w\/\&\.\-\%\>]{0,32}/
  condition:
    any of them
}
