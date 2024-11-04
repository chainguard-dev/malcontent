rule autorun: high {
  meta:
    description             = "Accesses Windows Start Menu"
    hash_1985_build_stealer = "d49043306ff8d6b394c6f39d70bd208ad740a6030d3cc5b5427d03cc7e494e7f"
    hash_1985_src_stealer   = "9af37b5973ee1e683d9708591cbe31b8a1044aab88b92b5883bdd74bcf8d807b"

  strings:
    $ref = "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
	$ref2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"

  condition:
    any of them
}
