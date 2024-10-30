rule html: medium {
  meta:
    description                  = "Contains HTML content"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_adminer    = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_root       = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"

  strings:
    $ref  = "<html>"
    $ref2 = "<img src>"
    $ref3 = "<a href>"
    $ref4 = "DOCTYPE html"
    $ref5 = "<html lang"

  condition:
    any of them
}
