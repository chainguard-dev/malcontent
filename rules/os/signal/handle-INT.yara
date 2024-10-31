rule sigaction_SIGINT: harmless {
  meta:
    description = "Listen for SIGINT (ctrl-C) events"

  strings:
    $sigaction = "sigaction" fullword
    $sigalrm   = "SIGINT"

  condition:
    all of them
}
