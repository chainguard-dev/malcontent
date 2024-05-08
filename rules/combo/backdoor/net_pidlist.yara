
rule proc_listpids_and_curl : suspicious macos {
  strings:
    $proc_listpids = "proc_listpids"
    $libcurl = "libcurl"
  condition:
    all of them
}
