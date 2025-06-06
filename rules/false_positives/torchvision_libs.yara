rule libpng_override: override {
  meta:
    description          = "libpng16.ca116d9f.so.16"
    upx_antiunpack_elf64 = "harmless"

  strings:
    $libpng1 = "Application built with libpng-"
    $libpng2 = "libpng version"
    $libpng3 = "0123456789ABCDEFlibpng warning: %s"
    $libpng4 = "libpng16.so.16"

  condition:
    all of them
}

rule libwebp_override: override {
  meta:
    description          = "libwebp.16dd7af3.so.7"
    upx_antiunpack_elf64 = "harmless"

  strings:
    $libwebp = "libwebp.so.7"
    $webp1   = "WebP"
    $webp2   = "WEBP"
    $webp3   = "webp_dec.c"

  condition:
    all of them
}
