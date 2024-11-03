rule server_addr: medium {
  meta:
    description = "may execute a shell and communicate with a server"

  strings:
    $serverAddr    = "serverAddr"
    $server_addr   = "server_addr"
    $exec          = "exec"
    $sh            = "/bin/sh" fullword
    $sh_bash       = "/bin/bash" fullword
    $sh_zsh        = "/bin/zsh" fullword
    $sh_script     = "ShellScript"
    $sh_exec       = "ExecShell"
    $sh_cmd        = "cmd.exe"
    $sh_powershell = "powershell.exe"

  condition:
    filesize < 10MB and any of ($server*) and $exec and any of ($sh*)
}

rule server_addr_small: high {
  meta:
    description = "may execute a shell and communicate with a server"

  strings:
    $serverAddr    = "serverAddr"
    $server_addr   = "server_addr"
    $exec          = "exec"
    $sh            = "/bin/sh" fullword
    $sh_bash       = "/bin/bash" fullword
    $sh_zsh        = "/bin/zsh" fullword
    $sh_script     = "ShellScript"
    $sh_exec       = "ExecShell"
    $sh_cmd        = "cmd.exe"
    $sh_powershell = "powershell.exe"

  condition:
    filesize < 128KB and any of ($server*) and $exec and any of ($sh*)
}
