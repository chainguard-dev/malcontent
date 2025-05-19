rule chattr_caller: medium {
  meta:
    filetypes = "service"

  strings:
    $chattr = /chattr [-\+][\w\- ]{0,32} [\w\.\/]{0,64}/

  condition:
    $chattr
}

rule chattr_immutable_caller_high: high {
  meta:
    description = "modifies immutability of a file"

    filetypes = "service"

  strings:
    $chattr  = /chattr [-\+]i [\-\w\.\/]{0,64}/
    $not_dev = "chattr -i /sys"

  condition:
    $chattr and none of ($not*)
}

rule chattr_immutable_caller_recursive: high {
  meta:
    description = "recursively removes immutability of a directory"
    ref         = "https://man7.org/linux/man-pages/man1/chattr.1.html"

  strings:
    $chattr_r_i = /chattr -R -i [\-\w\.\/]{0,64}/
    $chattr_ri  = /chattr -Ri [\-\w\.\/]{0,64}/
    $chattr_ir  = /chattr -iR [\-\w\.\/]{0,64}/
    $chattr_i_r = /chattr -i -R [\-\w\.\/]{0,64}/

  condition:
    filesize < 10MB and any of them
}
