rule selinux: medium {
  meta:
    description = "alters the SELinux enforcement level"

  strings:
    $ref1 = "SELINUX" fullword
    $ref2 = "setenforce" fullword

  condition:
    any of them
}
