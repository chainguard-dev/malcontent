rule dyntamic_lib: medium {
  meta:
    description              = "References a library file that can be generated dynamically"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

    hash_2023_pycryptoenv_ffi = "e26437e820c049cf7bd30c77fdd5fcfed44c8d8ff22f540f73005e7c13f0c428"

  strings:
    $ref = "/lib/%s"

  condition:
    $ref
}
