rule wolfictl_binary : override {
  meta:
    curl_tor_chmod_relative_run = "high"
    description = "wolfictl"
    original_severity = "critical"
  strings:
    $chainguard = "chainguard.dev"
    $false_positive_string = "domaingophertelnetreturn.locallisten.onionndots:sendtoip"
    $wolfi = "github.com/wolfi-dev"
    $wolfictl_repo = "github.com/wolfi-dev/wolfictl"
    $wolfictl = "wolf-dev/wolfictl"
  condition:
    all of them
}
