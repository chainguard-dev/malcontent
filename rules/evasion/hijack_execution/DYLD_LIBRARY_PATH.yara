rule dyld_library_path: medium {
  meta:
    hash_2017_5_QtCore = "d697c055b965e261483cbecf44c2a47b822caccf0c386d5e1c4f4fbbba9ab129"

  strings:
    $ref = "DYLD_LIBRARY_PATH"

  condition:
    any of them
}
