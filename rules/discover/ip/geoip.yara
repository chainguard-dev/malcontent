rule geoip_website_value: high {
  meta:
    description = "public service for IP geolocation"

  strings:
    $p_ipify     = "ip-api.com"
    $p_wtfismyip = "freegeoip"
    $p_geo       = "geolocation-db.com"

    $not_pypi_index = "testpack-id-lb001"

  condition:
    any of ($p*) and none of ($not*)
}
