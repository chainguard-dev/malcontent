rule host_processor_info: medium {
  meta:
    syscall                           = "host_processor_info"
    description                       = "returns hardware processor, count"
    ref                               = "https://developer.apple.com/documentation/kernel/1502854-host_processor_info"
    hash_2024_Downloads_0f66          = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_CoinMiner_com_adobe_acc = "fabe0b41fb5bce6bda8812197ffd74571fc9e8a5a51767bcceef37458e809c5c"
    hash_2023_CoinMiner_lauth         = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"

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
