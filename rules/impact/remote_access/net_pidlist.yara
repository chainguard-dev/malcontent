rule proc_listpids_and_curl: high macos {
  meta:
    description = "lists processes and uses curl"

  strings:
    $proc_listpids = "proc_listpids"
    $libcurl       = "libcurl"

  condition:
    all of them
}
