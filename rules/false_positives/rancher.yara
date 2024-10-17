rule pull_scripts : override {
  meta:
    curl_chmod_relative_run_tiny = "medium"
    description = "pull-scripts"
  strings:
    $downloading = "echo \"Downloading charts-build-scripts version ${CHARTS_BUILD_SCRIPTS_REPO}@${CHARTS_BUILD_SCRIPT_VERSION}\""
    $pulling = "echo \"Pulling in charts-build-scripts version ${CHARTS_BUILD_SCRIPTS_REPO}@${CHARTS_BUILD_SCRIPT_VERSION}\""
    $s_binary_name = "BINARY_NAME=\"charts-build-scripts_${OS}_${ARCH}.exe\""
    $s_chmod = "chmod +x ./bin/charts-build-scripts"
    $s_echo_name = "echo \"${BINARY_NAME} => ./bin/charts-build-scripts\""
    $s_version = "./bin/charts-build-scripts --version"
  condition:
    all of ($s*) and $downloading or $pulling
}
