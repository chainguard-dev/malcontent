
rule utimes : medium {
  meta:
    syscall = "utimes"
    pledge = "fattr"
    ref = "https://linux.die.net/man/2/utimes"
    description = "change file last access and modification times"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
  strings:
    $ref = "utimes" fullword
    $ref2 = "utime" fullword
  condition:
    any of them
}

rule futimes : medium {
  meta:
    syscall = "futimes"
    pledge = "fattr"
    description = "change file timestamps"
    ref = "https://linux.die.net/man/3/futimes"
    hash_2023_CoinMiner_com_adobe_acc = "fabe0b41fb5bce6bda8812197ffd74571fc9e8a5a51767bcceef37458e809c5c"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2018_MonoBundle_libMonoPosixHelper = "fb5b95f9bdb10fe39b5ae9e709099809e26a3359292436f4b329b372754743f3"
  strings:
    $ref = "futimes" fullword
  condition:
    any of them
}

rule lutimes : medium {
  meta:
    syscall = "lutimes"
    pledge = "fattr"
    description = "change file timestamps"
    ref = "https://linux.die.net/man/3/futimes"
    hash_2018_MonoBundle_libMonoPosixHelper = "fb5b95f9bdb10fe39b5ae9e709099809e26a3359292436f4b329b372754743f3"
    hash_2018_MonoBundle_libMonoPosixHelper = "fb5b95f9bdb10fe39b5ae9e709099809e26a3359292436f4b329b372754743f3"
  strings:
    $ref = "lutimes" fullword
  condition:
    any of them
}

rule utimensat {
  meta:
    syscall = "utimensat"
    pledge = "fattr"
    description = "change file timestamps with nanosecond precision"
    ref = "https://linux.die.net/man/3/futimens"
  strings:
    $ref = "utimensat" fullword
  condition:
    any of them
}

rule futimens {
  meta:
    syscall = "futimens"
    pledge = "fattr"
    description = "change file timestamps with nanosecond precision"
    ref = "https://linux.die.net/man/3/futimens"
  strings:
    $ref = "futimens" fullword
  condition:
    any of them
}

rule shell_toucher : medium {
  meta:
    description = "change file timestamps"
    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Linux_Malware_Samples_df3b = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
  strings:
    $ref = /touch [\$\%\w\-\_\.\/ ]{0,24}/ fullword
    $not_touch_a = "touch a"
  condition:
    $ref and none of ($not*)
}
