rule freeradius_server_checkrad: override {
  meta:
    description                                            = "/usr/bin/checkrad - FreeRADIUS NAS session checker using finger protocol"
    DITEKSHEN_INDICATOR_SUSPICIOUS_Finger_Download_Pattern = "harmless"

  strings:
    $freeradius = "This is used by the FreeRADIUS server to check"
    $checkrad   = "Usage: checkrad nas_type nas_ip"

  condition:
    filesize < 50000 and all of them
}
