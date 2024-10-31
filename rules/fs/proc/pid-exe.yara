rule proc_exe: high {
  meta:
    description                       = "accesses underlying executable of other processes"
    hash_2023_OK_4f5c                 = "4f5cfb805feb7576e594f1bb3b773ba0ca80e09e49bfb7e3507f815f774ac62d"
    hash_2023_Pupy_2ab5               = "2ab59fa690e502a733aa1500a96d8e94ecb892ed9d59736cca16a09538ce7d77"
    hash_2023_Unix_Dropper_Mirai_58c5 = "58c54ded0af2fffb8cea743d8ec3538cecfe1afe88d5f7818591fb5d4d2bd4e1"

  strings:
    $string = "/proc/%s/exe" fullword
    $digit  = "/proc/%d/exe" fullword
    $python = "/proc/{}/exe" fullword

  condition:
    any of them
}
