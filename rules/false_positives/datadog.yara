rule ddtrace_rules_json : override {
  meta:
    description = "appsec/rules.json"
    linux_multi_persist = "medium"
  strings:
    $datadog = /[Dd]atadog/
    $datadog_generic = /[Dd]atadog \w{0,32}/
    $datadog_test_scanner = "Datadog test scanner"
  condition:
    all of them
}
