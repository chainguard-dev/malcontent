rule html: medium {
  meta:
    description = "Contains HTML content"

    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"

  strings:
    $ref  = "<html>"
    $ref2 = "<img src>"
    $ref3 = "<a href>"
    $ref4 = "DOCTYPE html"
    $ref5 = "<html lang"

  condition:
    any of them
}
