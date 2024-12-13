import "math"

rule proc_s_cmdline: high {
  meta:
    description = "access command-line of other processes"

  strings:
    $string = "/proc/%s/cmdline" fullword

  condition:
    any of them
}

rule proc_d_cmdline: high {
  meta:
    description = "access command-line of other processes"

  strings:
    $digit = "/proc/%d/cmdline" fullword

  condition:
    any of them
}

rule proc_cmdline_override: override {
  meta:
    proc_d_cmdline = "medium"
    proc_s_cmdline = "medium"

  strings:
    $POLKIT_IS_UNIX_USER = "POLKIT_IS_UNIX_USER" fullword
    $NUMASTAT_WIDTH      = "NUMASTAT_WIDTH" fullword
    $polkit_unix         = "polkit_unix"
    $cloudinit           = "cloudinit" fullword

  condition:
    any of them
}

rule proc_py_cmdline: high {
  meta:
    description = "access command-line of other processes"

  strings:
    $python = "/proc/{}/cmdline" fullword

  condition:
    any of them
}

rule proc_cmdline_near: high {
  meta:
    description = "access command-line for other processes"

  strings:
    $proc  = "/proc" fullword
    $fmt   = "cmdline" fullword
    $fmt_d = "%d" fullword

  condition:
    all of them and math.abs(@proc - @fmt) < 64 and math.abs(@fmt - @fmt_d) < 64
}
