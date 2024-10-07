rule melange_binary : override {
  meta:
    curl_tor_chmod_relative_run = "high"
    description = "melange"
    downgrade = "true"
    original_severity = "critical"
  strings:
    $chainguard = "chainguard.dev"
    $dev = "github.com/chainguard-dev"
    $false_positive_string = "domaingophertelnetreturn.locallisten.onionndots:sendtoip"
    $melange = "chainguard.dev/melange"
  condition:
    all of them
}
