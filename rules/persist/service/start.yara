rule service_start {
  strings:
    $ref           = /service [\w\_\- ]{1,16} start/
    $not_osquery   = "OSQUERY"
    $not_not_start = "service not start"
    $not_must      = "service name must start"

  // $ref also matches the English phrases "service not start" / "service name
  // must start", so presence of those cannot disqualify the whole file. Each
  // phrase accounts for exactly one $ref match, so compare occurrence counts and
  // fire only on a $ref hit neither phrase explains. OSQUERY stays independent.

  condition:
    $ref and #ref > #not_not_start + #not_must and not $not_osquery
}
