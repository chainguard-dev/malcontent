rule protobuf: harmless {
  strings:
    $ref = "protobuf" fullword

  condition:
    any of them
}
