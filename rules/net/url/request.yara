rule requests_urls: medium {
  meta:
    description             = "requests resources via URL"
    hash_2023_botbait       = "1b92cb3d4b562d0eb05c3b2f998e334273ce9b491bc534d73bcd0b4952ce58d2"
    hash_2023_misc_mktmpio  = "f6b7984c76d92390f5530daeacf4f77047b176ffb8eaf5c79c74d6dd4d514b2b"
    hash_2023_misc_mr_robot = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"

  strings:
    $ref   = "NSMutableURLRequest"
    $ref2  = "import requests"
    $ref3  = "net/url"
    $ref4  = /requests\.get\([\w, =\)]{0,16}/
    $ref5  = "require('request');"
    $ref6  = "request(url, "
    $ref7  = "require('https').request"
    $ref8  = "http.request"
    $ref9  = "urllib2.urlopen"
    $ref10 = "urllib.request"
    $ref11 = "require 'httparty'"
    $ref12 = "HTTParty.get"

  condition:
    any of them
}
