rule listens_and_executes_shell: high {
  meta:
    description                          = "Listens at a port and executes shells"
    hash_2024_Downloads_8cad             = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2023_Linux_Malware_Samples_3668 = "3668b167f5c9083a9738cfc4bd863a07379a5b02ee14f48a10fb1240f3e421a6"

  strings:
    $f_socket        = "socket" fullword
    $f_execl         = "execl" fullword
    $f_execve        = "execve" fullword
    $f_exec_unix     = "exec_unix" fullword
    $f_inet_addr     = "inet_addr" fullword
    $f_inet_addr2    = "getaddrinfo" fullword
    $f_listen        = "listen" fullword
    $f_listen_accept = "accept" fullword
    $f_listentcp     = "TCPListen"
    $sh_bash         = "bash" fullword
    $sh_zsh          = "zsh" fullword
    $sh_script       = "ShellScript"
    $sh_exec         = "ExecShell"
    $sh_cmd          = "cmd.exe"
    $not_setlocale   = "setlocale" fullword
    $not_ptrace      = "ptrace" fullword

  condition:
    filesize < 10MB and any of ($f_sock*) and any of ($f_exec*) and any of ($f_inet*) and any of ($f_listen*) and any of ($sh*) and none of ($not*)
}

rule go_tcp_listen_and_exec_shell: high {
  meta:
    description = "Listens at a port and executes a shell"

  strings:
    $run    = "os/exec.(*Cmd).Run"
    $listen = "net.(*TCPListener).Accept"
    $bash   = "/bin/bash"

  condition:
    filesize < 10MB and all of them
}
