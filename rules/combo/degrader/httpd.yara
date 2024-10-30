rule win_kill_proc_likely: high linux {
  meta:
    description = "httpd killer, may block future attackers from entry"

  strings:
    $ref = "killall httpd"

  condition:
    uint32(0) == 1179403647 and filesize < 1MB and $ref
}
