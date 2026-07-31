rule systemd_no_blank_lines: high {
  meta:
    ref       = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    filetypes = "service"

  strings:
    $execstart  = "ExecStart"
    $not_blank  = "\n\n"
    $not_apport = "ExecStart=/usr/share/apport/apport"

  condition:
    // $not_blank is the structural premise of the rule, so it stays an absolute
    // negation; $not_apport contains "ExecStart" itself, so count past it and a
    // trojaned apport unit with an extra ExecStart line still fires
    filesize < 4096 and $execstart and not $not_blank and #execstart > #not_apport
}
