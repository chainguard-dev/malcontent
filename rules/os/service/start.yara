rule service_start {
  strings:
    $ref           = /service [\w\_\- ]{1,16} start/
    $not_osquery   = "OSQUERY"
    $not_not_start = "service not start"
    $not_must      = "service name must start"

  condition:
    $ref and none of ($not*)
}
