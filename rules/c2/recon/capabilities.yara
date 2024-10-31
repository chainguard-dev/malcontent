
rule process_capabilities_val : medium {
  meta:
    description = "enumerates Linux capabilities for process"
    hash_2024_enumeration_deepce = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
  strings:
    $capsh = "capsh" fullword
    $self_status = "/proc/self/status"
  condition:
    all of them
}
