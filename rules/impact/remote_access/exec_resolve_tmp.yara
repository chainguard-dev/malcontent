rule fexecve_gethostbyname_realpath_tmp: critical {
  meta:
    description              = "Runs programs, resolves hosts and paths, uses /tmp"
    hash_2024_Downloads_59f9 = "59f959b1e69f988171152f99eb636f9b360712234457072f78c1c08d41e1460e"

  strings:
    $f1  = "fexecve" fullword
    $f2  = "gethostbyname" fullword
    $f3  = "realpath" fullword
    $tmp = "/tmp/"

  condition:
    $tmp and all of ($f*) in (1000..3000)
}
