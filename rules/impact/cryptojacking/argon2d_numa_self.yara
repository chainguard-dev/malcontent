rule probably_a_miner: high {
  meta:
    description = "probably a cryptocurrency miner"

  strings:
    $argon     = "argon2d"
    $proc_self = "/proc/self"
    $numa      = "NUMA"

  condition:
    filesize < 10MB and all of them
}
