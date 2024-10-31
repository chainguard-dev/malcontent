rule kcore: unusual {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access physical memory of the system in core file format"

  strings:
    $val = "/proc/kcore"

  condition:
    any of them
}

