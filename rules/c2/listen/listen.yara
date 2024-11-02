rule listening_for_client_shell: high {
  strings:
    $client    = "Waiting for client"
    $listen    = "listen"
    $server    = "server"
    $exec      = "exec"
    $sh        = "sh" fullword
    $sh_bash   = "bash" fullword
    $sh_zsh    = "zsh" fullword
    $sh_script = "ShellScript"
    $sh_exec   = "ExecShell"
    $sh_cmd    = "cmd.exe"

  condition:
    filesize < 10MB and any of ($client*) and $listen and $server and $exec and any of ($sh*)
}
