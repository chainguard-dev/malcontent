rule etc_shadow: medium {
  meta:
    description = "accesses /etc/shadow"

    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"

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
