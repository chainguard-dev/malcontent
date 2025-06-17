rule kobalos_override: override {
  meta:
    description                        = "webhook"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  strings:
    $knative1 = "knative.dev/operator"
    $knative2 = "knative.dev/pkg/webhook"
    $knative3 = "main.newConversionController"

  condition:
    all of them
}
