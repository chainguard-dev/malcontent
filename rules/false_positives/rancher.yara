rule pull_scripts : override {
  meta:
    curl_chmod_relative_run_tiny = "medium"
    description = "pull-scripts"
  strings:
    $binary_name = "BINARY_NAME=charts-build-scripts" fullword
  condition:
    all of them
}
