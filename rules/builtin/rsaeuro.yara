
rule rsaeuro_user : notable {
  strings:
    $toolkit = "RSAEURO Toolkit"
  condition:
    any of them
}
