rule kmod: medium linux {
  meta:
    description = "Linux kernel module source code"

    filetypes = "c,h,hh"

  strings:
    $ref              = "<linux/kmod.h>"
    $not_define_linux = "#define _LINUX_MODULE_H"

  condition:
    $ref and none of ($not*)
}
