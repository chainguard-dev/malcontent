rule collect_data: medium {
  meta:
    description              = "Uses terms that reference data collection"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"

  strings:
    $ref  = "collect_data"
    $ref2 = "CollectData"
    $ref3 = "DataCollection"

  condition:
    any of them
}
