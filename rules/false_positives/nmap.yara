rule nmap_fingerprints: override {
  meta:
    description                                 = "http-fingerprints.lua"
    SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell = "medium"
    meterpreter                                 = "medium"
    grayware_sites                              = "medium"

  strings:
    $description = "---HTTP Fingerprint files"
    $license     = "This file is released under the Nmap license"
    $fingerprint = /fingerprint.{0,32}/

  condition:
    filesize < 512KB and $description and $license and #fingerprint > 0
}

rule nping_bin: override {
  meta:
    description               = "/usr/bin/nping"
    SEKOIA_Tool_Nping_Strings = "medium"

  strings:
    $nping = "Usage: nping [Probe mode] [Options] {target specification}"
    $site  = "https://nmap.org/nping"

  condition:
    filesize < 1MB and all of them
}
