rule zstd {
  meta:
    description = "Zstandard: fast real-time compression algorithm"

  strings:
    $ref         = "zstd" fullword
    $decompress  = "ZSTD_decompressStream" fullword
    $magic_bytes = { 28 B5 2F FD }

  condition:
    any of them
}
