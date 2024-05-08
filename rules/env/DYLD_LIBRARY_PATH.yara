
rule dyld_library_path : notable {
  meta:
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2017_5_QtCore = "d697c055b965e261483cbecf44c2a47b822caccf0c386d5e1c4f4fbbba9ab129"
    hash_2017_5_QtNetwork = "b036f1961fde73644001e5fa5ca5c414339f86c2ae084b031b6d5259a50ae696"
  strings:
    $ref = "DYLD_LIBRARY_PATH"
  condition:
    any of them
}
