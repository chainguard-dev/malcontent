rule geoip_website_value : suspicious {
  meta:
	description = "public service for IP geolocation"
  strings:
    $ipify = "ip-api.com"
    $wtfismyip = "freegeoip"
  condition:
    any of them
}
