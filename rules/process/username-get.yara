rule getlogin {
  meta:
    syscall     = "getlogin"
    description = "get login name"
    pledge      = "id"
    ref         = "https://linux.die.net/man/3/getlogin"

  strings:
    $ref  = "getlogin" fullword
    $ref2 = "getpass.getuser" fullword

  condition:
    any of them
}

rule whoami: medium {
  meta:
    syscall                              = "getuid"
    description                          = "returns the user name running this process"
    ref                                  = "https://man7.org/linux/man-pages/man1/whoami.1.html"
    hash_2023_misc_mr_robot              = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2023_Linux_Malware_Samples_3292 = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"

  strings:
    $ref = "whoami" fullword

  condition:
    any of them
}
