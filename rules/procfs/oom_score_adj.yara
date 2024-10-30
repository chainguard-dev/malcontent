rule oom_score_adj: harmless {
  meta:
    capability  = "CAP_SYS_RESOURCE"
    description = "access OOM (out-of-memory) settings"

  strings:
    $ref = "oom_score_adj" fullword

  condition:
    any of them
}
