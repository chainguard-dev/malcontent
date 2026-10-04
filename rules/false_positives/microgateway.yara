rule microgateway_test_fixtures: override {
  meta:
    description       = "Apigee Edge Microgateway config/tests/fixtures/*.js"
    http_hardcoded_ip = "low"

  strings:
    $eval_org  = /victorshaw-eval-test\.apigee\.net/
    $helloecho = /edgemicro_helloecho/
    $node01    = /'\/node01'/

  condition:
    filesize < 8KB and all of them
}
