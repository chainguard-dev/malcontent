rule host_processor_info: medium {
  meta:
    syscall     = "host_processor_info"
    description = "returns hardware processor, count"
    ref         = "https://developer.apple.com/documentation/kernel/1502854-host_processor_info"

  strings:
    $ref = "host_processor_info"

  condition:
    any of them
}

rule host_processors {
  meta:
    syscall     = "host_processors"
    description = "returns hardware processor, count"
    ref         = "https://developer.apple.com/documentation/kernel/1502854-host_processor_info"

  strings:
    $ref = "host_processors"

  condition:
    any of them
}

rule processor_count {
  meta:
    description = "gets number of processors"
    ref         = "https://man7.org/linux/man-pages/man3/get_nprocs.3.html"

  strings:
    $ref  = "get_nprocs" fullword
    $ref2 = "nproc" fullword
    $ref3 = "numProcessors" fullword

  condition:
    any of them
}

rule nproc: harmless {
  meta:
    description = "gets number of processors"
    ref         = "https://man7.org/linux/man-pages/man3/get_nprocs.3.html"

  strings:
    $ref2 = "nproc" fullword

  condition:
    any of them
}
