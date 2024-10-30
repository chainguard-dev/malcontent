rule perf_event_open {
  meta:
    capability  = "CAP_SYS_PERFMON"
    description = "set up performance monitoring"

  strings:
    $ref = "perf_event_open" fullword

  condition:
    any of them
}
