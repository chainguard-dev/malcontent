rule systemd_no_blank_lines: high {
  meta:
    ref                         = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"

  strings:
    $execstart  = "ExecStart"
    $not_blank  = "\n\n"
    $not_apport = "ExecStart=/usr/share/apport/apport"

  condition:
    filesize < 4096 and $execstart and none of ($not*)
}
