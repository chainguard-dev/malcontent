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

rule ps_exec_pipe: high {
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

  strings:
    $shell  = "ls /proc" fullword
    $python = "os.listdir('/proc')"

  condition:
    any of them
}

rule proclist: medium {
  meta:
    description = "accesses process list"

  strings:
    $proclist       = "proclist" fullword
    $gops           = "shirou/gopsutil"
    $running        = "RunningProcesses"
    $GetProcessList = /\w{0,5}ProcessList/

  condition:
    any of them
}

rule java_lang_processes_opaque: medium {
  meta:
    description = "accesses process list"
    filetypes   = "jar,java"

  strings:
    $processes = "processes" fullword
    $lang      = "java/lang/Process"

  condition:
    filesize < 2MB and all of them
}

rule generic_process_list: medium {
  meta:
    description = "accesses process list"

  strings:
    $pl  = "ProcessList"
    $pl2 = "processList"
    $al  = "allProcesses"
    $lp  = "listProcesses"
    $lp2 = "ListProcesses"

  condition:
    filesize < 10MB and any of them
}
