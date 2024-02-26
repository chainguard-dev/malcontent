rule syn_cookie : suspicious {
  strings:
    $syncookie = "syncookie"
    $syn_cookie = "syn_cookie"
  condition:
    any of them
}
