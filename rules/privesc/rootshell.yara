
rule rootshell : high {
  meta:
    description = "references a root shell"
    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"
  strings:
    $ref = "rootshell"
    $ref2 = "r00tshell"
  condition:
    any of them
}
