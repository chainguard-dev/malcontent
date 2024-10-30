rule usbmon_webproxy_zipper: high {
  meta:
    hash_2023_KandyKorn_kandykorn = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"

  strings:
    $usbmon    = "usbmon" fullword
    $webproxy  = "WebProxy"
    $web_proxy = "webproxy"
    $zip       = "zip" fullword

  condition:
    $usbmon and $zip and any of ($web*)
}
