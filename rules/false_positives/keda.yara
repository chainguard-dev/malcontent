rule keda_adapter: override {
  meta:
    description                        = "keda-adapter - KEDA metrics API server adapter"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  strings:
    $keda_module = "github.com/kedacore/keda/v2"
    $keda_cmd    = "github.com/kedacore/keda/v2/cmd/adapter"

  condition:
    filesize < 200MB and all of them
}
