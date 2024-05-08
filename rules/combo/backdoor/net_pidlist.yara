
rule proc_listpids_and_curl : suspicious macos {
  meta:
    hash_2023_KandyKorn_kandykorn = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"
  strings:
    $proc_listpids = "proc_listpids"
    $libcurl = "libcurl"
  condition:
    all of them
}
