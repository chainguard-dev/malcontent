
rule macos_kitchen_sink_binary {
  strings:
    $f_sysctl = "sysctl"
    $f_mkdtemp = "mkdtemp"
    $f_mktemp = "mktemp"
    $f_inet_addr = "inet_addr"
    $f_waitpid = "waitpid"
    $f_proc_listpids = "proc_listpids"
    $f_kill = "kill"
    $f_chdir = "chdir"
    $f_setsockopt = "setsockopt"
    $f_getpid = "getpid"
    $f_unlink = "unlink"
    $f_chmod = "chmod"
    $not_osquery = "OSQUERY"
  condition:
    90% of ($f*) and none of ($not*)
}

rule ssh_socks5_exec : notable {
  meta:
    description = "supports SOCKS5, SSH, and executing programs"
  strings:
    $socks5 = "Socks5"
    $ssh = "crypto/ssh"
    $exec = "os/exec.Command"
  condition:
    filesize < 67108864 and all of them
}

rule progname_socket_waitpid : suspicious {
  meta:
    description = "sets process name, accesses internet, calls programs"
  strings:
    $dlsym = "__progname" fullword
    $openpty = "socket" fullword
    $system = "waitpid" fullword
  condition:
    all of them in (1200..3000)
}

rule POST_command_executer : suspicious {
  strings:
    $post = "POST"
    $command_executed = "Command executed"
  condition:
    all of them
}

rule exec_getprog_socket_waitpid_combo {
  strings:
    $execle = "_execl"
    $execve = "_execve"
    $f_fork = "_fork"
    $f_getpid = "_getpid"
    $f_inet = "_inet_ntoa"
    $f_getprog = "_getprogname"
    $f_gethostbyname = "_gethostbyname"
    $f_socket = "_socket"
    $f_waitpid = "_waitpid"
    $f_rand = "_random"
  condition:
    8 of ($f*) and 1 of ($exec*)
}

rule exec_chdir_and_socket : notable {
  strings:
    $socket = "socket" fullword
    $chdir = "chdir" fullword
    $execl = "execl" fullword
    $execve = "execve" fullword
    $not_environ = "environ" fullword
  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $chdir and $socket and 1 of ($exec*) and none of ($not*)
}

rule listens_and_executes : notable {
  meta:
    description = "Listens, provides a terminal, runs program"
  strings:
    $f_socket = "socket" fullword
    $f_execl = "execl" fullword
    $f_inet_addr = "inet_addr" fullword
    $f_listen = "listen" fullword
    $not_setlocale = "setlocale" fullword
    $not_ptrace = "ptrace" fullword
    $not_usage = "Usage:"
  condition:
    all of ($f*) and none of ($not*)
}
