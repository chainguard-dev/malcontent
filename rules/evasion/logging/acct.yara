rule acct {
  meta:
    capability  = "CAP_SYS_ACCT"
    description = "switch process accounting on or off"

  strings:
    $ref = "acct" fullword

    // from /etc/services
    $not_radius = "radius-acct" fullword

  condition:
    any of them
}
