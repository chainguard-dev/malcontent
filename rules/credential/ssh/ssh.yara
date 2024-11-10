rule ssh_folder: medium {
  meta:
    ref                                                                                  = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description                                                                          = "accesses SSH configuration and/or keys"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35                                                             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_e100                                                             = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"

  strings:
    $slash = "/.ssh"
    $re    = /[\~\$\%\{\}\w\/]{0,16}\.ssh[\w\/]{0,16}/ fullword
    $pkg   = /[a-z]{2,16}\.ssh/

  condition:
    filesize < 20MB and $slash or ($re and not $pkg)
}

rule id_rsa: medium {
  meta:
    description = "accesses SSH private keys"

  strings:
    $id_rsa = "id_rsa" fullword

  condition:
    filesize < 10MB and ssh_folder and $id_rsa
}

rule id_rsa_not_ssh: high {
  meta:
    description = "non-SSH client accessing SSH private keys"

  strings:
    $id_rsa            = "id_rsa" fullword
    $not_ssh_newkeys   = "SSH_MSG"
    $not_ssh_userauth  = "SSH_USERAUTH"
    $not_ssh_20        = "SSH-2.0"
    $not_openssh       = "OpenSSH"
    $not_ssh2          = "SSH2" fullword
    $not_SSH_AUTH_SOCK = "SSH_AUTH_SOCK"

  condition:
    filesize < 10MB and ssh_folder and $id_rsa and none of ($not*)
}
