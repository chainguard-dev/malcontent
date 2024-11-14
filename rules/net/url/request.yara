rule requests_urls: medium {
  meta:
    description            = "requests resources via URL"
    hash_2023_botbait      = "1b92cb3d4b562d0eb05c3b2f998e334273ce9b491bc534d73bcd0b4952ce58d2"


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
