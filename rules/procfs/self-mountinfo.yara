rule proc_self_mountinfo : medium {
  meta:
    description = "gets mount info associated to this process"
    pledge = "stdio"
  strings:
    $ref = "/proc/self/mountinfo"
  condition:
    $ref
}
