rule proc_maps: medium {
  meta:
    description              = "access process memory maps"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_Downloads_abf0 = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_c91c = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"

  strings:
    $string = "/proc/%s/maps" fullword
    $digit  = "/proc/%d/maps" fullword
    $python = "/proc/{}/maps" fullword

  condition:
    any of them
}
