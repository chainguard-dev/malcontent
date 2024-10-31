rule selinux: medium {
  meta:
    hash_2023_Downloads_6e35             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_450a = "450a7e35f13b57e15c8f4ce1fa23025a7c313931a394c40bd9f3325b981eb8a8"
    hash_2023_Qubitstrike_branch_raw_mi  = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $ref1 = "SELINUX" fullword
    $ref2 = "setenforce" fullword

  condition:
    any of them
}
