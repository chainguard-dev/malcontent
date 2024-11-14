rule ufw: medium {
  meta:
    description = "interacts with the ufw firewall"

  strings:
    $ref = "ufw" fullword

    $arg_disable = "disable" fullword
    $arg_allow   = "allow" fullword
    $arg_deny    = "deny" fullword
    $arg_enable  = "enable" fullword

  condition:
    $ref and any of ($arg*)
}
