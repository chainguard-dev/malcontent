rule bssid {
  meta:
    description = "wireless network base station ID"

  strings:
    $ref  = "BSSID"
    $ref2 = "bssid"

  condition:
    any of them
}

rule wpa_supplicant {
  meta:
    description = "access WPA encrypted wireless networks"
    ref         = "https://wiki.archlinux.org/title/wpa_supplicant"

  strings:
    $ref = "wpa_supplicant"

  condition:
    any of them
}

rule wps_supplicant {
  meta:
    description = "access WPS encrypted wireless networks"
    ref         = "https://wiki.archlinux.org/title/wps_supplicant"

  strings:
    $ref = "wps_supplicant"

  condition:
    any of them
}
