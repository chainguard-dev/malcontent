
rule var_root_path : high macos {
  meta:
    description = "path reference within /var/containers"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
  strings:
    $ref = /\/var\/containers\/[\%\w\.\-\/]{4,32}/ fullword
  condition:
    $ref
}
