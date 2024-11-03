rule reverse_shell: high {
  meta:
    description                                                                               = "references a reverse shell"
    hash_2023_0xShell_wesoori                                                                 = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_ciscotools_4247                                                                 = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"
    hash_2023_OK_ad69                                                                         = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2024_D3m0n1z3dShell_demonizedshell                                                   = "d7c34b9d711260c1cd001ca761f5df37cbe40b492f198b228916b6647b660119"
    hash_2024_locutus_borg_transwarp                                                          = "4573af129e3e1a197050e2fd066f846c92de64d8d14a81a13d975a2cbc6d391e"

  strings:
    $r_bash_dev_tcp         = "bash -i >& /dev/tcp/"
    $r_reverse_or_web_shell = /(r[e3]v[e3]rs[e3]|w[3e]b)\s*sh[e3]ll/ nocase
    $r_reverse_shell        = "reverse_shell"
    $r_reverse_space_shell  = "reverse shell" nocase fullword
    $r_revshell             = "revshell"
    $r_stdin_redir          = "0>&1" fullword
    $not_ref_1              = "reverse shellConf"
    $not_ref_2              = "reverse shellshare"

  condition:
    any of ($r_*) and none of ($not_*)
}

rule possible_reverse_shell: medium {
  meta:
    description = "references a reverse shell"

  strings:
    $f_reverse = "reverse"
    $f_socket  = "socket" fullword
    $sh_bash   = "/bin/bash"
    $sh        = "/bin/sh"

  condition:
    filesize < 4MB and any of ($sh*) and all of ($f*)
}

rule mkfifo_netcat: critical {
  meta:
    description = "creates a reverse shell using mkfifo and netcat"

  strings:
    $mkfifo = "mkfifo" fullword
    $sh_i   = "sh -i"
    $nc     = /\| {0,2}nc /

  condition:
    filesize < 16384 and all of them
}

rule perl_reverse_shell: critical {
  meta:
    hash_2023_Win_Trojan_Perl_9aed = "9aed7ab8806a90aa9fac070fbf788466c6da3d87deba92a25ac4dd1d63ce4c44"
    hash_2023_uacert_socket        = "912dc3aee7d5c397225f77e3ddbe3f0f4cf080de53ccdb09c537749148c1cc08"
    hash_2024_raas_raas_test       = "58829e93da60b0934d7739d1a6aba92d665ac72bab9efc0571c0fc9751d40f3e"

  strings:
    $socket       = "socket("
    $open         = "open("
    $redir_double = "\">&"
    $redir_single = "'>&"
    $sh_i         = "sh -i"

  condition:
    $socket and $open and any of ($redir*) and $sh_i
}

rule go_reverse_shell: high {
  meta:
    description = "possible reverse shell written in Go"

  strings:
    $sh_bash    = "/bin/bash"
    $sh         = "/bin/sh"
    $f_cmd_run  = "os/exec.(*Cmd).Run"
    $f_net_conn = "net.(*conn).Write"
    $f_stdin    = "os/exec.(*Cmd).childStdin"
    $f_tcp      = "dialTCP"

  condition:
    filesize < 4MB and any of ($sh*) and all of ($f*)
}
