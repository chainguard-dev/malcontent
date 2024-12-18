rule http_port_443: high {
  meta:
    description = "hardcoded HTTP site on port 443 (HTTPS)"

  strings:
    $http_443       = /http:\/\/[\w\.]{0,32}:443[\/\w\-\?\.]{0,32}/
    $not_test       = "assertEqual"
    $not_example    = "http://example.com:443"
    $not_localhost  = "http://localhost:443"
    $not_foo        = "http://foo.com:443/"
    $not_empty      = "http://:443/"
    $not_slash_test = "/test" fullword
    $not_unit_test  = "unit test"

  condition:
    $http_443 and none of ($not*)
}
