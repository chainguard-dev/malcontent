rule kuma_cp: override {
  meta:
    description  = "kuma-cp - Kuma service mesh control plane"
    ESET_Kobalos = "harmless"

  strings:
    $kuma_module = "github.com/kumahq/kuma"
    $kuma_io     = "kuma.io"

  condition:
    filesize < 250MB and all of them
}
