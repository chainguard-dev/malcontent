
rule nohup_reference_value : medium {
  meta:
    description = "Runs command that is protected from termination"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Linux_Malware_Samples_3059 = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2023_Linux_Malware_Samples_553a = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
  strings:
    $nohup = "nohup" fullword
    $nohup_re_val = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append = "appending output"
    $not_usage = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd = "pushd"
  condition:
    filesize < 52428800 and any of ($nohup*) and none of ($not*)
}

rule elf_nohup : high {
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
    uint32(0) == 1179403647 and filesize < 1MB and any of ($nohup*) and none of ($not*)
}

rule trap_1 : high {
  meta:
    description = "Protects itself from early termination via SIGHUP"
    hash_2023_Linux_Malware_Samples_3059 = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2023_Linux_Malware_Samples_553a = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2023_Linux_Malware_Samples_7a60 = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
  strings:
    $ref = "trap '' 1"
    $ref2 = "trap \"\" 1"
  condition:
    any of them
}

rule nohup_bash : high {
  meta:
    description = "Calls bash with nohup"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Malware_Agent_b79a = "b79af4e394cbc8c19fc9b5410fa69b10325fd23f58bec330954caae135239a1f"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
  strings:
    $ref = /nohup bash[ \w\/\&\.\-\%\>]{0,32}/
  condition:
    any of them
}
