
rule kmod : high {
  meta:
    description = "includes Linux kernel module source code"
    hash_2024_enumeration_deepce = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"
  strings:
    $ref = "<linux/kmod.h>"
  condition:
    any of them
}
