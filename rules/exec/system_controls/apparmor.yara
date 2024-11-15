rule apparmor: medium {
  meta:
    description = "Mentions 'apparmor'"

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
