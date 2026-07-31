rule usr_sbin_telnetd: high {
  meta:
    description = "References /usr/sbin/telnetd"

  strings:
    $ref          = "/usr/sbin/telnetd"
    // neighbouring entries in BusyBox's concatenated applet path table; either
    // one on its own says nothing about why telnetd is referenced, so the pair
    // is required as a set
    $not_dos2unix = "/usr/bin/dos2unix"
    $not_setfont  = "/usr/sbin/setfont"

  condition:
    $ref and not all of ($not*)
}
