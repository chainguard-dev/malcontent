rule uses_pseudo_rng: medium {
  meta:
    description = "uses a fast pseudorandom generator"
    filetypes   = "elf,go,macho"

  strings:
    $ethers = "valyala/fastrand"

  condition:
    filesize < 10MB and all of them
}
