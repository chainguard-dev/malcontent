rule libz {
  strings:
    $lib_dylib = "libz.1.dylib"

  condition:
    any of them
}

