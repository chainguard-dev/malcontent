rule root_path_val: medium {
  meta:
    description = "path reference within /root"

  strings:
    $root           = /\/root\/[%\w\.\-\/]{0,64}/
    $root2          = "/root" fullword
    $not_go_selinux = "SELINUXTYPE"

  condition:
    any of them and none of ($not*)
}
