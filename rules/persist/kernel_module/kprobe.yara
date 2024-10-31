rule register_kprobe: medium {
  meta:
    description                          = "registers a kernel probe (possibly kernel module)"
    hash_2022_LQvKibDTq4_diamorphine     = "aec68cfa75b582616c8fbce22eecf463ddb0c09b692a1b82a8de23fb0203fede"
    hash_2023_LQvKibDTq4_diamorphine     = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"
    hash_2023_LQvKibDTq4_diamorphine_mod = "710368bd25889cb1d61ce82ac59c4cc076ea8021f9d3c47bb6ae79ca2901bdc2"

  strings:
    $ref = "register_kprobe"

  condition:
    any of them
}
