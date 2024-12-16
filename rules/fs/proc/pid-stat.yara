import "math"

rule proc_pid_stat: medium {
  meta:
    description = "access status fields for other processes"

  strings:
    $string = "/proc/%s/stat" fullword
    $digit  = "/proc/%d/stat" fullword
    $python = "/proc/{}/stat" fullword

  condition:
    any of them
}

rule proc_pid_stat_near: medium {
  meta:
    description = "access status fields for other processes"

  strings:
    $proc = "/proc" fullword
    $fmt  = /%[sd]\/stat/ fullword

  condition:
    all of them and math.abs(@proc - @fmt) < 128
}
