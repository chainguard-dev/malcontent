rule dl_iterate_cpu_pthreads: high linux {
  meta:
    description = "possible backdoor interested in shared libraries and CPU info"

  strings:
    $iterate   = "dl_iterate_phdr" fullword
    $pthread   = "pthread" fullword
    $nprocs    = "nprocs_cpu" fullword
    $chattr    = "chattr" fullword
    $osrelease = "/proc/sys/kernel/osrelease"

  condition:
    filesize < 1200KB and uint32(0) == 1179403647 and all of them
}

