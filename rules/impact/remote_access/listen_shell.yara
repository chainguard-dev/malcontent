rule listens_and_executes_shell: medium {
  meta:
    description = "Listens at a port and executes shells"

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
    $not_image_jpeg  = "image/jpeg"
    $not_openpgp     = "openpgp"
    $not_dbus        = "dbus" fullword

  condition:
    filesize < 3MB and any of ($f_sock*) and any of ($f_exec*) and any of ($f_inet*) and any of ($f_listen*) and any of ($sh*) and none of ($not*)
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

rule ruby_listen_command: high {
  meta:
    description = "Listens at a port and executes commands"

  strings:
    $loop  = "tcp_server_loop"
    $ruby2 = /\.popen\w{0,2}\(["'\w \.\#\{\}]{0,64}/

  condition:
    filesize < 4MB and all of them
}
