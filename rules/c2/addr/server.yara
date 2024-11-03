rule server_addr: high {
  strings:
    $serverAddr  = "serverAddr"
    $server_addr = "server_addr"
    $exec        = "exec"
    $sh          = "sh" fullword
    $sh_bash     = "bash" fullword
    $sh_zsh      = "zsh" fullword
    $sh_script   = "ShellScript"
    $sh_exec     = "ExecShell"
    $sh_cmd      = "cmd.exe"

  condition:
    filesize < 10MB and any of ($server*) and $exec and any of ($sh*)
}
