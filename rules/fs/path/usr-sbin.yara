rule usr_sbin_path {
  meta:
    description = "path reference within /usr/sbin"

  strings:
    $resolv = /\/usr\/sbin\/[\w\.\-\/]{0,64}/

  condition:
    any of them
}
