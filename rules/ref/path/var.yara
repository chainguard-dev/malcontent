rule var_path {
  meta:
    description = "path reference within /var"

  strings:
    $resolv = /\/var\/[%\w\.\-\/]{0,64}/

  condition:
    any of them
}
