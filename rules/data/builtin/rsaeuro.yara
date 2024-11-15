rule rsaeuro_user: medium {
  meta:
    description = "includes the RSAEURO toolkit"

  strings:
    $toolkit = "RSAEURO Toolkit"

  condition:
    any of them
}
