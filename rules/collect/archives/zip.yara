rule zip: medium {
  meta:
    description                     = "Works with zip files"
    hash_2024_Downloads_7c63        = "7c636f1c9e4d9032d66a58f263b3006788047488e00fc26997b915e9d1f174bf"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Downloads_e6b6        = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"

  strings:
    $ref  = "ZIP64" fullword
    $ref2 = "archive/zip"
    $ref3 = "zip_writer" fullword
    $ref4 = "ZIP archive" fullword
    $ref5 = "zip files" fullword

  condition:
    any of them
}
