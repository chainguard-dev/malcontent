rule systemd_no_blank_lines: high {
  meta:
    ref       = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    filetypes = "service"

  strings:
    $execstart  = "ExecStart"
    $not_blank  = "\n\n"
    $not_apport = "ExecStart=/usr/share/apport/apport"

  condition:
    filesize < 4096 and $execstart and none of ($not*)
}
