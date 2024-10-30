rule service_stop {
  strings:
    $ref           = /service [\w\_\- ]{1,16} stop/
    $not_osquery   = "OSQUERY"
    $not_not_start = "service not stop"

  condition:
    $ref and none of ($not*)
}
