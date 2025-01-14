rule wireshark: override {
  meta:
    BlackTech_Hipid_str = "low"

  strings:
    $wireshark = "wireshark"

  condition:
    filesize < 200MB and #wireshark > 25
}
