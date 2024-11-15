rule implant: medium {
  meta:
    description = "References an Implant"

  strings:
    $ref            = "implant" fullword
    $ref2           = "IMPLANT" fullword
    $ref3           = "Implant"
    $not_ms_example = "Drive-by Compromise"

  condition:
    any of ($ref*) and none of ($not*)
}
