rule usr_bin_path {
  meta:
    description = "path reference within /usr/bin"

  strings:
    $ref = /\/usr\/bin\/[\w\.\-]{0,32}/

  condition:
    any of them
}
