rule library_injector: high {
  meta:
    description = "may inject code into other processes"

  strings:
    $proc          = "/proc"
    $maps          = "maps"
    $inject_lib    = "to-inject"
    $inject_thread = "to inject"
    $inject_succ   = "successfully injected"

  condition:
    filesize < 100KB and $proc and $maps and any of ($inject*)
}
