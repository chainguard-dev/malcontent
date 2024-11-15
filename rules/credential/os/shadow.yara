rule etc_shadow: medium {
  meta:
    description = "accesses /etc/shadow"

  strings:
    $ref            = /\/{0,1}etc\/shadow/
    $not_vim        = "VIMRUNTIME"
    $not_go_selinux = "SELINUXTYPE"

  condition:
    $ref and none of ($not*)
}

rule npm_etc_shadow: high {
  meta:
    description = "accesses /etc/shadow from NPM package"

  strings:
    $ref     = /\/{0,1}etc\/shadow/
    $name    = "\"name\":"
    $scripts = "\"scripts\":"

  condition:
    filesize < 16KB and $ref and $name and $scripts
}

rule getspnam: low {
  meta:
    description = "verifies passwords against /etc/shadow"

  strings:
    $getspnam = "getspnam@" fullword

  condition:
    filesize < 1MB and any of them
}
