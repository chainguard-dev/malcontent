
rule proc_probe_with_ps : notable {
  meta:
    description = "Checks if a process ID is running"
    hash_2021_CDDS_installer_v2021 = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
    hash_2021_CDDS_kAgent = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
  strings:
    $ps_pid = "ps -p %"
    $hash_bang = "#!"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_apple = "com.apple."
  condition:
    any of ($ps*) and not $hash_bang in (0..2) and none of ($not*)
}
