rule trap_1: high {
  meta:
    description = "Protects itself from early termination via SIGHUP"

  strings:
    $ref                = "trap '' 1"
    $ref2               = "trap \"\" 1"
    $not_netcat_example = "ignore most signals; the parent will nuke the kid"

  condition:
    any of ($ref*) and none of ($not*)
}
