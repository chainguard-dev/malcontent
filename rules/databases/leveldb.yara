
rule leveldb : medium {
  meta:
    description = "accesses LevelDB databases"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
  strings:
    $ref = /[\w]{0,16}leveldb[\w]{0,16}/ fullword
    $ref2 = /[\w]{0,16}LevelDB[\w]{0,16}/ fullword
    $ref3 = /[\w]{0,16}LEVELDB[\w]{0,16}/ fullword
  condition:
    any of them
}
