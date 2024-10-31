rule usr_path: harmless {
  meta:
    description = "path reference within /usr/"

  strings:
    $ref              = /\/usr\/[\w\.\-\/]{0,64}/
    $not_lib_go       = "/usr/lib/go"
    $not_local_go     = "/usr/local/go"
    $not_local_lib_go = "/usr/local/lib/go"
    $not_include      = "/usr/include"

  condition:
    $ref and none of ($not*)
}
