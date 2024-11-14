rule dial_shared_screen_discovery: high {
  meta:
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"

  strings:
    $urn_multiscreen = "urn:dial-multiscreen-org:service:dial:1"
    $not_chromium    = "RasterCHROMIUM"

  condition:
    $urn_multiscreen and none of ($not*)
}
