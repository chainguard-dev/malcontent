rule powertop: override {
  meta:
    description  = "/usr/bin/powertop"
    fake_kworker = "low"

  strings:
    $version   = /PowerTOP version /
    $cache_dir = /\/var\/cache\/powertop/

  condition:
    filesize < 5MB and all of them
}
