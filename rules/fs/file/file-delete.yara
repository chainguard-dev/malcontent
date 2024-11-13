rule unlink: posix {
  meta:
    pledge      = "wpath"
    syscall     = "unlink"
    description = "deletes files"
    ref         = "https://man7.org/linux/man-pages/man2/unlink.2.html"

  strings:
    $unlink   = "unlink" fullword
    $unlinkat = "unlinkat" fullword
    $py       = "os.remove("
    $objc     = "deleteFile" fullword

  condition:
    any of them
}

rule rm_f_hardcoded_tmp_path: medium posix {
  meta:
    ref                                                               = "https://attack.mitre.org/techniques/T1485/"
    hash_2023_BPFDoor_8b84                                            = "8b84336e73c6a6d154e685d3729dfa4e08e4a3f136f0b2e7c6e5970df9145e95"
    hash_2023_BPFDoor_8b9d                                            = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
    hash_2023_FontOnLake_FE26CB98AA1416A8B1F6CED4AC1B5400517257B2_elf = "bcfb4d908469db43ffd8370ebca6b3e8b75470fa997ef10b7a451fa3f489acae"

  strings:
    $ref     = /rm +\-[a-zA-Z]{,1}f[a-zA-Z]{,1} \/(tmp|var|dev)\/[\w\/\.\-\%]{0,64}/
    $not_apt = "/var/lib/apt/lists"

  condition:
    $ref and none of ($not*)
}

rule del: medium windows {
  meta:
    description = "deletes files"

  strings:
    $del            = "del "
    $cmd_echo       = "echo off"
    $cmd_powershell = "powershell"

  condition:
    filesize < 16KB and $del and any of ($cmd*)
}

rule DeleteFile: medium {
  meta:
    description = "delete a file"

  strings:
    $create = /DeleteFile\w{0,8}/

  condition:
    any of them
}
