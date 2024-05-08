
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
    hash_2024_Downloads_e100 = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
    hash_2023_UPX_5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59_elf_x86_64 = "56ca5d07fa2e8004a008222a999a97a6c27054b510e8dd6bd22048b084079e37"
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
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
  strings:
    $dlsym = "__progname" fullword
    $openpty = "socket" fullword
    $system = "waitpid" fullword
  condition:
    all of them in (1200..3000)
}

rule POST_command_executer : suspicious {
  meta:
    hash_2023_ObjCShellz_ProcessRequest = "8bfa4fe0534c0062393b6a2597c3491f7df3bf2eabfe06544c53bdf1f38db6d4"
    hash_2023_ObjCShellz_ProcessRequest_2 = "b8c751694945bff749b6a0cd71e465747402cfd25b18dc233c336e417b3e1525"
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
  meta:
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_4305 = "4305c04df40d3ac7966289cc0a81cedbdd4eee2f92324b26fe26f57f57265bca"
    hash_2023_Downloads_78eb = "78eb647f3d2aae5c52fcdc46ac1b27fb5a388ad39abbe614c0cfc902d223ccd6"
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
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2023_Linux_Malware_Samples_3668 = "3668b167f5c9083a9738cfc4bd863a07379a5b02ee14f48a10fb1240f3e421a6"
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
