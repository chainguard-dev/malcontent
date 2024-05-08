
rule dlsym : notable {
  meta:
    ref = "https://man7.org/linux/man-pages/man3/dlsym.3.html"
    description = "get the address of a symbol"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
  strings:
    $ref = "dlsym" fullword
  condition:
    any of them
}
