rule apparmor: medium {
  meta:
    description              = "Mentions 'apparmor'"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $ref = "apparmor" fullword

  condition:
    any of them
}

rule apparmor_stop: high {
  meta:
    description = "Stops the AppArmor service"

  strings:
    $val                   = "apparmor stop"
    $not_DistUpgradeQuirks = "DistUpgradeQuirks" fullword

  condition:
    $val and none of them
}

rule disable_apparmor: high {
  meta:
    description = "Disables the AppArmor service"

  strings:
    $val = "disable apparmor"

  condition:
    any of them
}
