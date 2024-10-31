rule sigprocmask: harmless {
  strings:
    $sigprocmask = "sigprocmask"

  condition:
    any of them
}
