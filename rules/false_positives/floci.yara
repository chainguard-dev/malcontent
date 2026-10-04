rule floci_healthcheck: override {
  meta:
    description               = "/usr/local/bin/healthcheck.sh probing the local floci port"
    bash_dev_tcp_hardcoded_ip = "low"
    bash_dev_tcp              = "low"

  strings:
    $health       = /\/_floci\/health/
    $dev_tcp_4566 = /\/dev\/tcp\/127\.0\.0\.1\/4566/

  condition:
    filesize < 1KB and all of them
}
