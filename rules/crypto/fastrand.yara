rule uses_pseudo_rng: medium {
  meta:
    description = "uses a fast pseudorandom generator"

  strings:
    $ethers = "valyala/fastrand"

  condition:
    filesize < 10MB and all of them
}
