rule utimes: medium {
  meta:
    syscall     = "utimes"
    pledge      = "fattr"
    ref         = "https://linux.die.net/man/2/utimes"
    description = "change file last access and modification times"

  strings:
    $ref  = "utimes" fullword
    $ref2 = "utime" fullword

  condition:
    any of them
}

rule futimes: medium {
  meta:
    syscall                           = "futimes"
    pledge                            = "fattr"
    description                       = "change file timestamps"
    ref                               = "https://linux.die.net/man/3/futimes"

    hash_2023_CoinMiner_lauth         = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"

  strings:
    $ref = "futimes" fullword

  condition:
    any of them
}

rule lutimes: medium {
  meta:
    syscall     = "lutimes"
    pledge      = "fattr"
    description = "change file timestamps"
    ref         = "https://linux.die.net/man/3/futimes"



  strings:
    $ref = "lutimes" fullword

  condition:
    any of them
}

rule utimensat {
  meta:
    syscall     = "utimensat"
    pledge      = "fattr"
    description = "change file timestamps with nanosecond precision"
    ref         = "https://linux.die.net/man/3/futimens"

  strings:
    $ref = "utimensat" fullword

  condition:
    any of them
}

rule futimens {
  meta:
    syscall     = "futimens"
    pledge      = "fattr"
    description = "change file timestamps with nanosecond precision"
    ref         = "https://linux.die.net/man/3/futimens"

  strings:
    $ref = "futimens" fullword

  condition:
    any of them
}

rule shell_toucher: medium {
  meta:
    description               = "change file timestamps"
    hash_2023_0xShell_root    = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"


  strings:
    $ref         = /touch [\$\%\w\-\_\.\/ ]{0,24}/ fullword
    $not_touch_a = "touch a"

  condition:
    $ref and none of ($not*)
}
