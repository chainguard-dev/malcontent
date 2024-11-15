rule usr_local_path: harmless {
  meta:
    description = "path reference within /usr/local"

  strings:
    $val = /\/usr\/local\/[\w\.\-\/]{0,64}/
    $go  = "/usr/local/go"

  condition:
    $val and not $go
}

rule usr_local_bin_path: medium {
  meta:
    description = "path reference within /usr/local/bin"

  strings:
    $val = /\/usr\/local\/bin[\w\.\-\/]{0,64}/

  condition:
    $val
}

rule usr_local_lib_path: medium {
  meta:
    description = "path reference within /usr/local/lib"

  strings:
    $val = /\/usr\/local\/lib[\w\.\-\/]{0,64}/

  condition:
    $val
}
