rule fexecve_gethostbyname_realpath_tmp: critical {
  meta:
    description = "Runs programs, resolves hosts and paths, uses /tmp"

  strings:
    $f1  = "fexecve" fullword
    $f2  = "gethostbyname" fullword
    $f3  = "realpath" fullword
    $tmp = "/tmp/"

  condition:
    $tmp and all of ($f*) in (1000..3000)
}
