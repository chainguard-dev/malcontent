rule base64_http_val: high {
  meta:
    description = "base64 HTTP protocol references"

  strings:
    $user_agent  = "User-Agent" base64
    $mozilla_5_0 = "Mozilla/5.0" base64
    $referer     = "Referer" base64
    $http_1_0    = "HTTP/1.0" base64
    $http_1_1    = "HTTP/1.1" base64

  condition:
    any of them
}
