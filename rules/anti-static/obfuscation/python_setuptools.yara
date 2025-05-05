import "math"

rule setuptools_builtins: medium {
  meta:
    description = "Python library installer that references builtins"
    filetypes   = "text/x-python"

  strings:
    $ref = "__builtins__" fullword

  condition:
    any of them
}
