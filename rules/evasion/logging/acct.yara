rule acct {
  meta:
    capability  = "CAP_SYS_ACCT"
    description = "switch process accounting on or off"

  strings:
    $ref = "acct" fullword

    // from /etc/services
    $not_radius = "radius-acct" fullword

  // $ref matches inside "radius-acct" as well, so compare occurrence counts
  // rather than presence, and never treat the exclusion as evidence.

  condition:
    $ref and #ref > #not_radius
}
