rule server_address: medium {
  meta:
    description = "references a 'server address', possible C2 client"

  strings:
    $s_underscores = /\w{0,32}server_addr\w{0,32}/
    $s_mixed       = /\w{0,32}serverAddr\w{0,32}/
    $s_url         = "serverURL" fullword
    $s_url2        = "serverUrl" fullword
    $s_connect     = /\w{0,32}ConnectServer\w{0,32}/

  condition:
    any of ($s*)
}

rule server_addr_small: medium {
  meta:
    description = "may execute a shell and communicate with a server"

  strings:
    $serverAddr       = "serverAddr"
    $server_addr      = "server_addr"
    $server_connected = "connected to server"
    $exec             = "exec"
    $sh               = "/bin/sh" fullword
    $sh_bash          = "/bin/bash" fullword
    $sh_zsh           = "/bin/zsh" fullword
    $sh_script        = "ShellScript"
    $sh_exec          = "ExecShell"
    $sh_cmd           = "cmd.exe"
    $sh_powershell    = "powershell.exe"

    $hash_bang = "#!"

  condition:
    filesize < 1MB and any of ($server*) and $exec and any of ($sh*) and not $hash_bang in (0..3)
}
