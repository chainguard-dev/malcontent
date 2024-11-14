rule php_no_time_limit: medium {
  meta:
    description = "disables execution time limit"

    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"

  strings:
    $ref = "set_time_limit(0)"

  condition:
    $ref
}
