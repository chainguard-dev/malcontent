rule etc_path {
  meta:
    description = "path reference within /etc"

  strings:
    $resolv = /\/etc\/[a-z\.\-\/]{4,32}/

  condition:
    any of them
}
