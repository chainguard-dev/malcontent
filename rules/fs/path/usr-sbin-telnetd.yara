rule usr_sbin_telnetd: high {
  meta:
    description = "References /usr/sbin/telnetd"

  strings:
    $ref          = "/usr/sbin/telnetd"
    $not_dos2unix = "/usr/bin/dos2unix"
    $not_setfont  = "/usr/sbin/setfont"

  condition:
    $ref and none of ($not*)
}
