rule proc_listallpids: medium {
  meta:
    pledge      = "exec"
    syscall     = "vfork"
    description = "calls proc_listallpid"

  strings:
    $ref = "proc_listallpid" fullword

  condition:
    any of them
}

rule ps_exec: medium {
  meta:
    pledge                           = "exec"
    syscall                          = "vfork"
    hash_2018_org_logind_ctp_archive = "02e4d0e23391bbbb75c47f5db44d119176803da74b1c170250e848de51632ae9"
    hash_2022_Gimmick_CorelDRAW      = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"

  strings:
    $ps_ef     = "ps -ef |"
    $ps__ax    = "ps -ax"
    $ps_ax     = "ps ax"
    $hash_bang = "#!"
    $not_node  = "NODE_DEBUG_NATIVE"
    $not_apple = "com.apple."

  condition:
    any of ($ps*) and not $hash_bang in (0..2) and none of ($not*)
}

rule procfs_listdir: medium {
  meta:
    pledge                          = "exec"
    syscall                         = "vfork"
    hash_2024_dumpcreds_mimipenguin = "79b478d9453cb18d2baf4387b65dc01b6a4f66a620fa6348fa8dbb8549a04a20"
    hash_2024_enumeration_linpeas   = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $shell  = "ls /proc" fullword
    $python = "os.listdir('/proc')"

  condition:
    any of them
}

rule proclist: medium {
  meta:
    description                          = "accesses process list"
    hash_2024_Downloads_0f66             = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_e241             = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2023_Linux_Malware_Samples_4c38 = "4c38654e08bd8d4c2211c5f0be417a77759bf945b0de45eb3581a2beb9226a29"

  strings:
    $proclist = "proclist" fullword
    $gops     = "shirou/gopsutil"
    $running  = "RunningProcesses"

  condition:
    any of them
}
