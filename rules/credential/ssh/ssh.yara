rule ssh_folder: medium {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "accesses SSH configuration and/or keys"

  strings:
    $slash  = "/.ssh"
    $slash2 = ".ssh/"
    $re     = /[\~\$\%\{\}\w\/]{0,16}\.ssh[\w\/]{0,16}/ fullword
    $pkg    = /[a-z]{2,16}\.ssh/

  condition:
    filesize < 20MB and any of ($slash*) or ($re and not $pkg)
}

rule id_rsa: medium {
  meta:
    description = "accesses SSH private keys"

  strings:
    $id_rsa = "id_rsa"

  condition:
    filesize < 20MB and ssh_folder and $id_rsa
}

rule id_rsa_not_ssh: high {
  meta:
    description = "non-SSH client accessing SSH private keys"

  strings:
    $id_rsa             = "id_rsa"
    $not_ssh_newkeys    = "SSH_MSG"
    $not_ssh_userauth   = "SSH_USERAUTH"
    $not_ssh_20         = "SSH-2.0"
    $not_openssh        = "OpenSSH"
    $not_ssh2           = "SSH2" fullword
    $not_SSH_AUTH_SOCK  = "SSH_AUTH_SOCK"
    $not_host_key_check = "host_key_check"
    $not_appsec_rules   = "\"id\": \"crs-930-120\""

  condition:
    filesize < 10MB and ssh_folder and $id_rsa and none of ($not*)
}
