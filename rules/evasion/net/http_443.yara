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
    // the four placeholder URLs are themselves $http_443 matches, so count past
    // them rather than exempting the file; the test markers match no URL and stay
    // absolute negations
    $http_443 and #http_443 > #not_example + #not_localhost + #not_foo + #not_empty and none of ($not_test, $not_slash_test, $not_unit_test)
}
