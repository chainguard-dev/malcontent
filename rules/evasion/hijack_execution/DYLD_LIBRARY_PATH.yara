rule dyld_library_path: medium {
  meta:
    hash_2017_5_QtCore    = "d697c055b965e261483cbecf44c2a47b822caccf0c386d5e1c4f4fbbba9ab129"
    hash_2017_5_QtNetwork = "b036f1961fde73644001e5fa5ca5c414339f86c2ae084b031b6d5259a50ae696"

  strings:
    $ref = "DYLD_LIBRARY_PATH"

  condition:
    any of them
}
