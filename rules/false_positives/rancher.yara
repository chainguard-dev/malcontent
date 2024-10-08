rule pull_scripts : override {
  meta:
    curl_chmod_relative_run_tiny = "medium"
    description = "pull-scripts"
  strings:
    $binary = "BINARY_NAME=\"charts-build-scripts_${OS}_${ARCH}.exe\""
    $chmod = "chmod +x ./bin/charts-build-scripts"
    $echo1 = "echo \"Downloading charts-build-scripts version ${CHARTS_BUILD_SCRIPTS_REPO}@${CHARTS_BUILD_SCRIPT_VERSION}\""
    $echo2 = "echo \"${BINARY_NAME} => ./bin/charts-build-scripts\""
    $version_cmd = "./bin/charts-build-scripts --version"
  condition:
    all of them
}
