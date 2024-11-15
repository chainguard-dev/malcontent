rule interface_testing_service_user: medium {
  meta:
    description = "accesses interface testing/developer backends"

  strings:
    $mockbin_org   = "mockbin.org"
    $run_mocky_io  = "run.mocky.io"
    $webhook_site  = "webhook.site"
    $devtunnels_ms = "devtunnels.ms"

  condition:
    any of them
}
