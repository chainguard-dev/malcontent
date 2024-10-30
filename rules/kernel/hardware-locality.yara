rule hwloc {
  meta:
    description = "Uses hardware locality (NUMA, etc)"
    ref         = "https://linux.die.net/man/7/hwloc"

  strings:
    $ref = "hwloc" fullword

  condition:
    any of them
}
