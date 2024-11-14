rule proc_status: medium {
  meta:
    description = "access status fields for other processes"

  strings:
    $string = "/proc/%s/status" fullword
    $digit  = "/proc/%d/status" fullword
    $python = "/proc/{}/status" fullword

  condition:
    any of them
}
