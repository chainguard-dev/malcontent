rule encoding_py_marshal: medium {
  meta:
    description = "reads python values from binary content"

  strings:
    $ref = /import{0,256} marshal/ fullword

  condition:
    filesize < 1MB and any of them
}

