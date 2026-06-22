rule lmcache_cuda_nixl: override {
  meta:
    description       = "NVIDIA NIXL test binaries in lmcache-cuda package"
    http_hardcoded_ip = "low"
    multiple_gcc      = "low"
    multiple_gcc_high = "low"

  strings:
    $nixl_agent = "nixlAgent"
    $nixl_lib   = "libnixl.so"

  condition:
    filesize < 200KB and all of them
}

rule nixl_object_test: override {
  meta:
    description       = "NIXL object storage test binary with example S3 endpoint in usage text"
    http_hardcoded_ip = "harmless"
    multiple_gcc      = "harmless"
    multiple_gcc_high = "harmless"

  strings:
    $nixl_storage = "NIXL Storage Test Pattern"
    $nixl_source  = "nixl_object_test.cpp"

  condition:
    filesize < 200KB and all of them
}

rule lmcache_nixl: override {
  meta:
    description       = "nixl_cu12 test/example binaries in lmcache-cuda package"
    bin_hardcoded_ip  = "harmless"
    hardcoded_ip      = "harmless"
    http_hardcoded_ip = "harmless"
    multiple_gcc      = "harmless"
    multiple_gcc_high = "harmless"

  strings:
    $nixl_cu12 = "nixl_cu12"
    $libnixl   = "libnixl.so"

  condition:
    filesize < 2MB and all of them
}
