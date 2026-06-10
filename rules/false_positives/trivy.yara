rule trivy: override {
  meta:
    description                        = "/usr/bin/trivy - Aqua Security vulnerability scanner"
    ESET_Kobalos                       = "harmless"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "harmless"

  strings:
    $trivy_module = "github.com/aquasecurity/trivy"
    $trivy_cmd    = "github.com/aquasecurity/trivy/cmd/trivy"

  condition:
    filesize < 350MB and all of them
}
