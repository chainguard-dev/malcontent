rule proc_probe_with_ps: medium {
  meta:
    description = "Checks if a process ID is running"

  strings:
    $ps_pid    = "ps -p %"
    $hash_bang = "#!"
    $not_node  = "NODE_DEBUG_NATIVE"
    $not_apple = "com.apple."

  condition:
    any of ($ps*) and not $hash_bang in (0..2) and none of ($not*)
}
