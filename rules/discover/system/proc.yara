rule proc_multiple: high {
  meta:
    description = "accesses an unusual assortment of /proc files"

  strings:
    $ref                   = /\/proc\/[%{$][\/\$\w\}]{0,12}/
    $stat                  = "/proc/stat"
    $net_den               = "/proc/net/dev"
    $proc_exe              = "/proc/%d/exe"
    $proc_kernel_v         = "/proc/sys/kernel/version"
    $proc_kernel_osrelease = "/proc/sys/kernel/osrelease"
    $proc_self_maps        = "/proc/self/maps"
    $proc_ngroups_max      = "/proc/sys/kernel/ngroups_max"
    $proc_rtsig_max        = "/proc/sys/kernel/rtsig-max"
    $proc_meminfo          = "/proc/meminfo"
    $proc_cpuinfo          = "/proc/cpuinfo"

  condition:
    filesize < 2MB and int32(0) == 1179403647 and 80 % of them
}
