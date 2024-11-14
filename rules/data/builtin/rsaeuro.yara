rule rsaeuro_user: medium {
  meta:

  strings:
    $toolkit = "RSAEURO Toolkit"

  condition:
    any of them
}
