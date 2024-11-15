rule contains_base64_url: medium {
  meta:
    description = "Contains base64 url"

  strings:
    $http  = "http://" base64
    $https = "https://" base64
    $tcp   = "tcp://" base64
    $udp   = "udp://" base64
    $ftp   = "ftp://" base64

  condition:
    any of them
}
