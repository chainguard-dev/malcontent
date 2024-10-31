rule interface_testing_service_user: medium {
  meta:
    hash_2022_dataclasses_python_version_1_0_0_setup = "abaae952f7bfee3ad0211d2fa641c84b93ff4252cdf12c111e188dd614245e31"
    hash_2023_gmgeoip_0_0_2_setup                    = "985e5d0cee86d818a820d6395308ad20a82361b57a055390a1dc921da0e53886"
    hash_2024_sln1550hello_0_0_2_setup               = "f5a079839ea580fb74333aba28425b8c0f4a374a8c05d815e0882e1f5967e2ce"

  strings:
    $mockbin_org   = "mockbin.org"
    $run_mocky_io  = "run.mocky.io"
    $webhook_site  = "webhook.site"
    $devtunnels_ms = "devtunnels.ms"

  condition:
    any of them
}
