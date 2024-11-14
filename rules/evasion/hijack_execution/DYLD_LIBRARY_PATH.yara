rule dyld_library_path: medium {
  meta:
  strings:
    $ref = "DYLD_LIBRARY_PATH"

  condition:
    any of them
}
