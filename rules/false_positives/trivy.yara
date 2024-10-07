rule trivy_binary : override {
  meta:
    curl_tor_chmod_relative_run = "high"
    description = "trivy"
    original_severity = "critical"
  strings:
    $aqua_security_trivy = "aquasecurity:trivy"
    $trivy_install = "# curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"
    $trivy_repo = "github.com/aquasecurity/trivy"
  condition:
    all of them
}
