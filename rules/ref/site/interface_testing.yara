
rule interface_testing_service_user : notable {
  strings:
    $mockbin_org = "mockbin.org"
    $run_mocky_io = "run.mocky.io"
    $webhook_site = "webhook.site"
    $devtunnels_ms = "devtunnels.ms"
  condition:
    any of them
}