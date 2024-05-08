
rule dirbuster : suspicious {
  meta:
    hash_2023_uacert_toolrefs = "63acea4dcef0084a9b6ccc17c56f712f32cfd3a5d752c7509fd0553177812a94"
  strings:
    $ref = "dirbuster" fullword
  condition:
    $ref
}
