rule requests_urls: medium {
  meta:
    description = "requests resources via URL"

  strings:
    $ = "NSMutableURLRequest"
    $ = "import requests"
    $ = "net/url"
    $ = /requests\.get\([\w, =\)]{0,16}/
    $ = "require('request');"
    $ = "request(url, "
    $ = "require('https').request"
    $ = "http.request"
    $ = "urllib2.urlopen"
    $ = "urllib.request"
    $ = "require 'httparty'"
    $ = "HTTParty.get"
    $ = "HTTP.get_response"
    $ = "OPEN_URL" fullword
    $ = "openUrl"
    $ = "openURL"

  condition:
    any of them
}
