rule make_setuid {
  meta:
    ref = "https://en.wikipedia.org/wiki/Setuid"

  strings:
    $chmod_47  = "chmod 47"
    $chmod_s   = "chmod +s"
    $setsuid   = "setSuid"
    $set_seuid = "set_suid"

  condition:
    any of them
}
