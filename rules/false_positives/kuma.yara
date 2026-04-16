rule kuma_cp: override {
  meta:
    description                        = "kuma-cp - Kuma service mesh control plane"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  strings:
    $kuma_module = "github.com/kumahq/kuma"
    $kuma_io     = "kuma.io"

  condition:
    filesize < 250MB and all of them
}
