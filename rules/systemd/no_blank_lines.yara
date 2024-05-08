
rule systemd_no_blank_lines : suspicious {
  meta:
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
  strings:
    $execstart = "ExecStart"
    $blank = "\n\n"
  condition:
    filesize < 4096 and $execstart and not $blank
}
