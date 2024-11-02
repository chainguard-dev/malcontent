rule macos_kitchen_sink_binary: medium {
  meta:
    hash_2023_KandyKorn_kandykorn = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"

  strings:
    $f_sysctl        = "sysctl"
    $f_mkdtemp       = "mkdtemp"
    $f_mktemp        = "mktemp"
    $f_inet_addr     = "inet_addr"
    $f_waitpid       = "waitpid"
    $f_proc_listpids = "proc_listpids"
    $f_kill          = "kill"
    $f_chdir         = "chdir"
    $f_setsockopt    = "setsockopt"
    $f_getpid        = "getpid"
    $f_unlink        = "unlink"
    $f_chmod         = "chmod"
    $not_osquery     = "OSQUERY"

  condition:
    filesize < 20971520 and 90 % of ($f*) and none of ($not*)
}

rule ssh_socks5_exec: medium {
  meta:
    description                                                                               = "supports SOCKS5, SSH, and executing programs"
    hash_2024_Downloads_e100                                                                  = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
    hash_2020_IPStorm_IPStorm_unpacked                                                        = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
    hash_2023_UPX_5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59_elf_x86_64 = "56ca5d07fa2e8004a008222a999a97a6c27054b510e8dd6bd22048b084079e37"

  strings:
    $socks5 = "Socks5"
    $ssh    = "crypto/ssh"
    $exec   = "os/exec.Command"

  condition:
    filesize < 67108864 and all of them
}

rule progname_socket_waitpid: high {
  meta:
    description              = "sets process name, accesses internet, calls programs"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $dlsym   = "__progname" fullword
    $openpty = "socket" fullword
    $system  = "waitpid" fullword

  condition:
    all of them in (1200..3000)
}

rule POST_command_executer: high {
  meta:
    hash_2023_ObjCShellz_ProcessRequest   = "8bfa4fe0534c0062393b6a2597c3491f7df3bf2eabfe06544c53bdf1f38db6d4"
    hash_2023_ObjCShellz_ProcessRequest_2 = "b8c751694945bff749b6a0cd71e465747402cfd25b18dc233c336e417b3e1525"

  strings:
    $post             = "POST"
    $command_executed = "Command executed"

  condition:
    all of them
}

rule exec_getprog_socket_waitpid_combo: high {
  meta:
    hash_2021_DoubleFantasy_mdworker = "502a80f81cf39f6c559ab138a39dd4ad5fca697dbca4a62b36527be9e55400f5"

  strings:
    $execle          = "_execl"
    $execve          = "_execve"
    $f_fork          = "_fork"
    $f_getpid        = "_getpid"
    $f_inet          = "_inet_ntoa"
    $f_getprog       = "_getprogname"
    $f_gethostbyname = "_gethostbyname"
    $f_socket        = "_socket"
    $f_waitpid       = "_waitpid"
    $f_rand          = "_random"

  condition:
    filesize < 262144000 and 8 of ($f*) and 1 of ($exec*)
}

rule exec_chdir_and_socket: medium {
  meta:
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_4305 = "4305c04df40d3ac7966289cc0a81cedbdd4eee2f92324b26fe26f57f57265bca"
    hash_2023_Downloads_78eb = "78eb647f3d2aae5c52fcdc46ac1b27fb5a388ad39abbe614c0cfc902d223ccd6"

  strings:
    $socket      = "socket" fullword
    $chdir       = "chdir" fullword
    $execl       = "execl" fullword
    $execve      = "execve" fullword
    $not_environ = "environ" fullword

  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $chdir and $socket and 1 of ($exec*) and none of ($not*)
}
