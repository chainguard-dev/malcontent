rule proc_probe_with_ps: medium {
  meta:
    description = "Checks if a process ID is running"

    hash_2021_CDDS_kAgent = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"

  strings:
    $ps_pid    = "ps -p %"
    $hash_bang = "#!"
    $not_node  = "NODE_DEBUG_NATIVE"
    $not_apple = "com.apple."

  condition:
    any of ($ps*) and not $hash_bang in (0..2) and none of ($not*)
}
