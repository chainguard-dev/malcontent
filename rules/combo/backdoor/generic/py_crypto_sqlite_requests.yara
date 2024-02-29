rule py_crypto_sqlite_requests : suspicious {
  meta:
    ref = "objective-see/GravityRAT/Enigma/Enigma"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2019_Enigma = "70454f1794ee4626a9d70f58aa570bca14da1c40432a2dd1bec5f51b0efcc13f"
  strings:
	$import = "import" fullword
    $bCrypto = "bCrypto" fullword
    $sqlite = "sqlite" fullword
    $requests = "requests" fullword
  condition:
    all of them
}