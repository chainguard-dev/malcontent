rule geoip_website_value: high {
  meta:
    description = "public service for IP geolocation"

    hash_2024_1337test_src_file = "6c6b24c0de3b232d3bb564237abb67a0951e3dc2e53aa2d2eaa583df8a710a1c"

  strings:
    $ipify     = "ip-api.com"
    $wtfismyip = "freegeoip"
    $geo       = "geolocation-db.com"

  condition:
    any of them
}
