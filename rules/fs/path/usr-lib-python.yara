rule usr_lib_python_path_val: medium {
  meta:
    description = "References paths within /usr/lib/python"

  strings:
    $ref = /\/usr\/lib\/python[\w\-\.\/]{0,128}/

  condition:
    $ref
}
