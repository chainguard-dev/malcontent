rule etc_initd: medium linux {
  meta:
    description = "references /etc/init.d"

  strings:
    $ref = /etc\/init\.d\/[\w\/\.]{0,32}/ fullword

  condition:
    filesize < 50MB and any of them
}

rule etc_initd_short_file: high linux {
  meta:
    description = "references short filename within /etc/init.d"

  strings:
    $ref      = /etc\/init\.d\/[a-z]{1,3}/ fullword
    $not_rcd  = "/etc/init.d/rc.d"
    $not_init = "SCRIPTNAME=/etc/init.d/"
    $header   = "### BEGIN INIT INFO"

  condition:
    // $ref's [a-z]{1,3} matches the "rc" in "/etc/init.d/rc.d", so count past that
    // literal instead of exempting the file outright
    filesize < 50MB and $ref and #ref > #not_rcd and not $not_init and not $header in (1..128)
}
