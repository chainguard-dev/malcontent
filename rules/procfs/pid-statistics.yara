rule proc_pid_stat_val {
  meta:
    description = "access process stats using /pid/%d/stat"

  strings:
    $string = "/proc/%s/stat" fullword
    $digit  = "/proc/%d/stat" fullword

  condition:
    any of them
}

