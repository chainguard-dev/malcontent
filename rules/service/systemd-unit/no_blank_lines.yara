rule systemd_no_blank_lines : suspicious {
  meta:
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    hash_2023_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
  strings:
    $execstart = "ExecStart"
    $blank = "\n\n"
  condition:
    filesize < 4KB and $execstart and not $blank
}
