rule dns_txt {
  meta:
    description = "Uses DNS TXT (text) records"

  strings:
    $dns = "dns"
    $txt = "TXT"

  condition:
    all of them
}
