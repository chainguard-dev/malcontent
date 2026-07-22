rule kubevela: override {
  meta:
    description                   = "KubeVela CLI and core manager binaries"
    MacOS_Trojan_Paradox_563594b2 = "harmless"

  strings:
    $oam_dev_kubevela = "github.com/oam-dev/kubevela"
    $kubevela_pkg     = "github.com/kubevela/pkg"

  condition:
    filesize < 200MB and all of them
}
