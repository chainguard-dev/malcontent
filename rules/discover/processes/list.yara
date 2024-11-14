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

rule ps_exec_pipe: critical {
  meta:
    description = "gets list of processes, isolating username, pid, ppid, cmdline"

  strings:
    $ps_ef = /ps -ef {0,2}\| {0,2}awk.{1,16}\$1.{1,5}\$2.{1,4}\$3.{1,4}\$8/

  condition:
    filesize < 25MB and any of them
}

rule ps_exec: medium {
  meta:
    pledge  = "exec"
    syscall = "vfork"

    hash_2022_Gimmick_CorelDRAW = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"

    description = "executes ps(1) for a list of processes"

  strings:
    $ps_ef     = "ps -ef"
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
    pledge  = "exec"
    syscall = "vfork"

    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $shell  = "ls /proc" fullword
    $python = "os.listdir('/proc')"

  condition:
    any of them
}

rule proclist: medium {
  meta:
    description              = "accesses process list"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"

  strings:
    $proclist       = "proclist" fullword
    $gops           = "shirou/gopsutil"
    $running        = "RunningProcesses"
    $GetProcessList = /\w{0,5}ProcessList/

  condition:
    any of them
}
