rule leveldb: medium {
  meta:
    description = "accesses LevelDB databases"

  strings:
    $ref  = /[\w]{0,16}leveldb[\w]{0,16}/ fullword
    $ref2 = /[\w]{0,16}LevelDB[\w]{0,16}/ fullword
    $ref3 = /[\w]{0,16}LEVELDB[\w]{0,16}/ fullword

  condition:
    any of them
}
