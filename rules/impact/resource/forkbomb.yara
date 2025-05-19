rule elf_pthread_forkbomb: high {
  meta:
    description = "may implement a pthread-based forkbomb"
    filetypes   = "elf"

  strings:
    $f_wait     = "wait" fullword
    $f_pthread  = "pthread_create" fullword
    $f_fork     = "fork" fullword
    $f_getpid   = "getpid" fullword
    $f_usleep   = "usleep" fullword
    $not_socket = "socket" fullword
    $not_execve = "execve" fullword

  condition:
    uint32(0) == 1179403647 and filesize < 20KB and all of ($f*) and none of ($not*)

}

rule elf_fork_usleep: high {
  meta:
    description = "may implement a forkbomb"
    filetypes   = "elf"

  strings:
    $f_wait     = "wait" fullword
    $f_pthread  = "pthread_create" fullword
    $f_fork     = "fork" fullword
    $f_getpid   = "getpid" fullword
    $f_usleep   = "usleep" fullword
    $not_socket = "socket" fullword
    $not_execve = "execve" fullword
    $not_usage  = "usage" fullword
    $not_Usage  = "Usage" fullword

  condition:
    uint32(0) == 1179403647 and filesize < 20KB and all of ($f*) and none of ($not*)

}
