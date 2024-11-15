rule dyld_library_path: medium {
  meta:
    description = "overrides the library search path"

  strings:
    $ref = "DYLD_LIBRARY_PATH"

  condition:
    any of them
}
