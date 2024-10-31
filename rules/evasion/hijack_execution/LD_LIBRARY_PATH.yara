rule ld_library_path {
  strings:
    $ref = "LD_LIBRARY_PATH" fullword

  condition:
    any of them
}
