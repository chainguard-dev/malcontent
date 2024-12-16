rule kernel_module_loader: medium linux {
  meta:
    description = "loads Linux kernel module via insmod"

  strings:
    $insmod = /insmod [ \#\{\}\$\%\w\.\/_-]{1,32}/

  condition:
    filesize < 10MB and all of them
}

rule kernel_module_loader_ko: high linux {
  meta:
    description = "loads Linux kernel module .ko via insmod"

  strings:
    $insmod = /insmod [ \$\%\w\.\/_-]{1,32}\.ko/

  condition:
    filesize < 10MB and all of them
}

rule kernel_module_loader_sus_redir: high linux {
  meta:
    description = "suspiciously loads Linux kernel module via insmod"

  strings:
    $insmod  = /insmod [ \$\%\w\.\/_-]{1,32} .{0,16}\/dev\/null 2\>\&1/
    $insmod2 = /insmod [ \$\%\w\.\/_-]{1,32} .{0,16}2>\/dev\/null/

  condition:
    filesize < 10MB and any of them
}

rule cha_cha_tests: override linux {
  meta:
    description             = "test_cipher.ko"
    filetypes               = "sh"
    kernel_module_loader_ko = "medium"

  strings:
    $test = "insmod test_cipher.ko size"

  condition:
    filesize < 2KB and any of them
}
