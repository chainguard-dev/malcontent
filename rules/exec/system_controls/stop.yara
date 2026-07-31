rule service_stop {
  strings:
    // a service name is a single token: allowing spaces made this match prose
    // such as "service manager of stop"
    $ref           = /service [\w\_\-]{1,16} stop/
    $not_osquery   = "OSQUERY"
    $not_not_start = "service not stop"

  condition:
    // "service not stop" is itself a $ref match, so compare counts: the prose
    // cancels its own occurrence and a real stop command still registers.
    // "OSQUERY" describes the whole file and stays a membership test.
    #ref > #not_not_start and not $not_osquery
}
