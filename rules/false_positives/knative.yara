import "hash"

rule kobalos_override: override {
  meta:
    description                        = "webhook"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  condition:
    (hash.sha256(0, filesize) == "572235f7943a8bab5377ed94c9dbdd8c2471e08e19ff6bc1edd0f1f3680ab25d")
}

rule knative_eventing_ingress: override {
  meta:
    description                        = "knative-eventing ingress binary"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  strings:
    $knative_eventing = "knative.dev/eventing"
    $ingress_module   = "knative.dev/eventing/cmd/broker/ingress"

  condition:
    filesize < 100MB and all of them
}
