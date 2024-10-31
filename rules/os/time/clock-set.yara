rule bsd_adjtime {
  meta:
    syscall     = "adjtime"
    pledge      = "settime"
    capability  = "CAP_SYS_TIME"
    description = "set time via system clock"

  strings:
    $adjtime = "adjtime" fullword

  condition:
    any of them
}

rule bsd_settimeofday {
  meta:
    syscall     = "settimeofday"
    capability  = "CAP_SYS_TIME"
    pledge      = "settime"
    description = "set time via system clock"

  strings:
    $settimeofday = "settimeofday" fullword

  condition:
    any of them
}

rule linux_adjtimex {
  meta:
    syscall     = "adjtimex"
    capability  = "CAP_SYS_TIME"
    pledge      = "settime"
    description = "set time via system clock"

  strings:
    $adjtimex = "adjtimex" fullword

  condition:
    any of them
}

rule linux_adjfreq {
  meta:
    syscall     = "adjfreq"
    pledge      = "settime"
    capability  = "CAP_SYS_TIME"
    description = "set time via system clock"

  strings:
    $adjfreq = "adjfreq" fullword

  condition:
    any of them
}

// there is also stime too, but it's deprecated
rule linux_clock_settime {
  meta:
    syscall     = "clock_settime"
    pledge      = "settime"
    capability  = "CAP_SYS_TIME"
    description = "set time via system clock"

  strings:
    $ref = "clock_settime" fullword

  condition:
    any of them
}
