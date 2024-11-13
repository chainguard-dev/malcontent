rule pull_scripts: override {
  meta:
    tool_chmod_relative_run_tiny = "medium"
    description                  = "pull-scripts"

  strings:
    $binary_name = "BINARY_NAME=charts-build-scripts"

  condition:
    all of them
}
