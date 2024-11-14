rule ufw: medium {
  meta:
    description              = "interacts with the ufw firewall"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_82f5 = "82f509473dbacadaeb2373b309566e7e1a46a67ae9d9c74159aa65bf6424ded8"

  strings:
    $ref = "ufw" fullword

    $arg_disable = "disable" fullword
    $arg_allow   = "allow" fullword
    $arg_deny    = "deny" fullword
    $arg_enable  = "enable" fullword

  condition:
    $ref and any of ($arg*)
}
