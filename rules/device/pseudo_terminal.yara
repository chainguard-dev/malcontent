
rule pty : notable {
  meta:
    description = "pseudo-terminal access functions"
    ref = "https://man7.org/linux/man-pages/man3/grantpt.3.html"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
  strings:
    $grantpt = "grantpt" fullword
    $ptsname = "ptsname" fullword
    $posix_openpt = "posix_openpt" fullword
    $unlockpt = "unlockpt" fullword
  condition:
    2 of them
}

rule go_pty : notable {
  meta:
    description = "pseudo-terminal access from Go"
    ref = "https://github.com/creack/pty"
    hash_2023_UPX_5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59_elf_x86_64 = "56ca5d07fa2e8004a008222a999a97a6c27054b510e8dd6bd22048b084079e37"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
  strings:
    $ref = "creack/pty"
  condition:
    any of them
}
