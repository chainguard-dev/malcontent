rule vmtools: override {
  meta:
    description         = "vmtools"
    backdoor            = "medium"
    proc_net_route_high = "medium"
    proc_s_exe          = "medium"
    sys_net_recon_exfil = "medium"
    proc_s_cmdline      = "medium"

  strings:
    $vmtools   = "VMTools" fullword
    $vmsupport = "VMSUPPORT" fullword
    $vmware    = "VMware" fullword

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and any of them
}
