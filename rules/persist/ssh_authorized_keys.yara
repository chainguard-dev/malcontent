rule ssh_authorized_key_val: medium {
  meta:
    ref                      = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description              = "access SSH authorized_keys"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $ssh_           = ".ssh" fullword
    $ssh2           = "authorized_keys"
    $not_ssh_client = "SSH_AUTH_SOCK"
    $not_example    = "/home/user/.ssh/authorized_keys"

  condition:
    all of ($ssh*) and none of ($not*)
}

rule root_authorized_keys: high {
  meta:
    description = "adds RSA keys to the root users authorized_keys file"

  strings:
    $root    = "root/.ssh/authorized_keys"
    $ssh_rsa = "ssh-rsa"

  condition:
    all of them
}
