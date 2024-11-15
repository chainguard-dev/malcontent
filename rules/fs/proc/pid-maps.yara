rule proc_maps: medium {
  meta:
    description = "access process memory maps"

  strings:
    $string = "/proc/%s/maps" fullword
    $digit  = "/proc/%d/maps" fullword
    $python = "/proc/{}/maps" fullword

  condition:
    any of them
}
