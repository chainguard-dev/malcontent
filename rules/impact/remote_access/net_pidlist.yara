rule proc_listpids_and_curl: high macos {
  meta:
  strings:
    $proc_listpids = "proc_listpids"
    $libcurl       = "libcurl"

  condition:
    all of them
}
