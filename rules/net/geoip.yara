
rule geoip_website_value : high {
  meta:
    description = "public service for IP geolocation"
    hash_2024_2021_ua_parser_js_preinstall = "156ee05a1c1c1c68441fb8eedc034c50293ff0a643a8a1c132363e612a08fa6d"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
    hash_2024_1337test_src_file = "6c6b24c0de3b232d3bb564237abb67a0951e3dc2e53aa2d2eaa583df8a710a1c"
  strings:
    $ipify = "ip-api.com"
    $wtfismyip = "freegeoip"
	$geo = "geolocation-db.com"
  condition:
    any of them
}
