rule interface_testing_service_user: medium {
  meta:
    hash_2023_gmgeoip_0_0_2_setup      = "985e5d0cee86d818a820d6395308ad20a82361b57a055390a1dc921da0e53886"


  strings:
    $mockbin_org   = "mockbin.org"
    $run_mocky_io  = "run.mocky.io"
    $webhook_site  = "webhook.site"
    $devtunnels_ms = "devtunnels.ms"

  condition:
    any of them
}
