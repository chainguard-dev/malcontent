rule rootshell: high {
  meta:
    description            = "references a root shell"
    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"

    hash_2024_Deobfuscated_WebShell_144c5d694fd42705ea4bcdb211e81478a4ca3598 = "e12a44da690194caed0fc8bdf8bf01f4a3ceff5ea19402638d61b81e59a4ba86"

  strings:
    $ref  = "rootshell"
    $ref2 = "r00tshell"

  condition:
    any of them
}
