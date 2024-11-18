rule var_containers_path: high macos {
  meta:
    description = "path reference within /var/containers"

  strings:
    $ref = /\/var\/containers\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    $ref
}
