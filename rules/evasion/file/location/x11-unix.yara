rule hidden_x11: medium {
  meta:
    description = "references content in /tmp/.X11-unix"
    ref         = "https://www.welivesecurity.com/2021/10/07/fontonlake-previously-unknown-malware-family-targeting-linux/"

  strings:
    $x11 = /\/tmp\/\.X11-unix\/[\.\w\%\$\{\}\/\-]{1,16}/

  condition:
    filesize < 10MB and all of them
}

rule hidden_x11_unexpected: high {
  meta:
    description = "references content in /tmp/.X11-unix"
    ref         = "https://www.welivesecurity.com/2021/10/07/fontonlake-previously-unknown-malware-family-targeting-linux/"

  strings:
    $x11 = /\/tmp\/\.X11-unix\/[\.\w\%\$\{\}\/\-]{1,16}/

    $not_usr_share   = "/usr/share/X11"
    $not_X11Gray     = "X11Gray"
    $not_etc         = "/etc/X11/"
    $not_X11R6       = "X11R6/share"
    $not_XForwarding = "X11 forwarding"
    $not_X           = "/tmp/.X11-unix/X" fullword
    $not_libx11      = "libX11.so.6"
    $not_XAUTHORITY  = "XAUTHORITY"

  // $x11 matches inside $not_X (the ordinary socket name), so referencing the
  // normal socket used to exempt every other path under /tmp/.X11-unix. Discount
  // $not_X by occurrence count instead; the other markers are each conclusive on
  // their own and stay presence checks.

  condition:
    filesize < 10MB and $x11 and #x11 > #not_X and none of ($not_usr_share, $not_X11Gray, $not_etc, $not_X11R6, $not_XForwarding, $not_libx11, $not_XAUTHORITY)
}
