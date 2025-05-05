rule write_open_http: high {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
    filetypes = "text/x-ruby"

  strings:
    $write_open_https = ".write(open('https://"
    $write_open_http  = ".write(open('http://"

  condition:
    any of them
}
