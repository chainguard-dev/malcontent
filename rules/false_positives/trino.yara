rule trino_launcher: override {
  meta:
    description                                     = "launcher"
    SIGNATURE_BASE_SUSP_ELF_LNX_UPX_Compressed_File = "high"

  strings:
    $go      = "go1.23"
    $module  = "/Users/martin/go/pkg"
    $partial = "martin/go"

  condition:
    filesize <= 1536KB and any of them
}
