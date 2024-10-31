rule kmod: medium linux {
  meta:
    description                  = "Linux kernel module source code"
    hash_2024_enumeration_deepce = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"
    filetypes                    = "c,h"

  strings:
    $ref              = "<linux/kmod.h>"
    $not_define_linux = "#define _LINUX_MODULE_H"

  condition:
    $ref and none of ($not*)
}
