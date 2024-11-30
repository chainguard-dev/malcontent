rule sysinfo: medium {
  meta:
    description = "get system information (load, swap)"
    syscall     = "sysinfo"
    ref         = "https://man7.org/linux/man-pages/man2/sysinfo.2.html"

  strings:
    $sysinfo    = "sysinfo" fullword
    $systeminfo = "systeminfo"

  condition:
    any of them
}
