rule base64_http_val: high {
  meta:
    description = "base64 HTTP protocol references"

  strings:
    $b_user_agent  = "User-Agent" base64
    $b_mozilla_5_0 = "Mozilla/5.0" base64
    $b_referer     = "Referer" base64
    $b_http_1_0    = "HTTP/1.0" base64
    $b_http_1_1    = "HTTP/1.1" base64

    $not_sourcemappingURL = "sourceMappingURL=data:application/json;charset=utf-8;base64"

  condition:
    any of ($b*) and none of ($not*)
}
