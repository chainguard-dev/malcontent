rule openfga: override {
  meta:
    description                        = "/usr/bin/openfga - OpenFGA authorization server"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  strings:
    $openfga_module = "github.com/openfga/openfga"
    $openfga_api    = "github.com/openfga/api/proto"

  condition:
    filesize < 100MB and all of them
}
