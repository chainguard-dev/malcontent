
rule pgrep : notable {
  meta:
    description = "Finds program in process table"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_060b = "060b01f15c7fab6c4f656aa1f120ebc1221a71bca3177f50083db0ed77596f0f"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $val = /pgrep[ \w\$]{0,32}/ fullword
  condition:
    $val
}
