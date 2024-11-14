rule process_capabilities_val: medium {
  meta:
    description                  = "enumerates Linux capabilities for process"
    hash_2024_enumeration_deepce = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"

  strings:
    $capsh       = "capsh" fullword
    $self_status = "/proc/self/status"

  condition:
    all of them
}
