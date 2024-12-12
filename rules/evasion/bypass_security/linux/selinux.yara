rule selinux: medium {
  meta:
    description = "alters the SELinux enforcement level"

  strings:
    $ref1 = "SELINUX"
    $ref2 = "setenforce"

  condition:
    all of them
}
