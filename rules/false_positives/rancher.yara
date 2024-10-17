rule pull_scripts : override {
  meta:
    curl_chmod_relative_run_tiny = "medium"
    description = "pull-scripts"
  strings:
    $binary_name = "BINARY_NAME=charts-build-scripts"
    $charts = "charts-build-scripts"
    $chmod = "chmod +x ./bin/charts-build-scripts"
    $echo_name = "echo \"${BINARY_NAME} => ./bin/charts-build-scripts\""
    $version = "./bin/charts-build-scripts --version"
  condition:
    all of them
}
