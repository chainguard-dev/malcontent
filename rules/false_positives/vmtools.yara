rule vmtools: override {
  meta:
    description                      = "vmtools"
    backdoor                         = "medium"
    linux_critical_system_paths_high = "medium"

  strings:
    $vmtools   = "VMTools_LoadConfig" fullword
    $vmsupport = "VMSUPPORT" fullword

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and any of them
}
