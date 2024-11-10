rule server_address: medium {
  meta:
    description                          = "references a 'server address', possible C2 client"
    hash_2024_Downloads_3105             = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Linux_Malware_Samples_450a = "450a7e35f13b57e15c8f4ce1fa23025a7c313931a394c40bd9f3325b981eb8a8"
    hash_2023_Linux_Malware_Samples_458e = "458e3e66eff090bc5768779d5388336c8619a744f486962f5dfbf436a524ee04"

  strings:
    $s_underscores = /\w{0,32}server_addr\w{0,32}/
    $s_mixed       = /\w{0,32}serverAddr\w{0,32}/
    $s_url         = "serverURL" fullword
    $s_url2        = "serverUrl" fullword
    $s_connect     = /\w{0,32}ConnectServer\w{0,32}/

  condition:
    any of ($s*)
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

    $hash_bang = "#!"

  condition:
    filesize < 1MB and any of ($server*) and $exec and any of ($sh*) and not $hash_bang in (0..3)
}
