rule vitess : override {
  meta:
    linux_multi_persist = "high"
    description = "vitess"
    original_severity = "critical"
  strings:
    $issue = "This error should not happen and is a bug. Please file an issue on GitHub: https://github.com/vitessio/vitess/issues/new/choose"
    $vitess = "vitess"
    $vitess_io = "vitess.io"
    $vitess_repo = "https://github.com/vitessio"
  condition:
    all of them
}
