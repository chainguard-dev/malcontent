rule geoip_website_value: high {
  meta:
    description = "public service for IP geolocation"

  strings:
    $ipify     = "ip-api.com"
    $wtfismyip = "freegeoip"
    $geo       = "geolocation-db.com"

  condition:
    any of them
}
