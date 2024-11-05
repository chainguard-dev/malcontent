rule curl_post: medium {
  meta:
    description = "uploads content using curl"

  strings:
    $curl  = "curl" fullword
    $post  = "-X POST"
    $https = "https://"
    $http  = "http://"

  condition:
    filesize < 8KB and $curl and $post and any of ($http*)
}

