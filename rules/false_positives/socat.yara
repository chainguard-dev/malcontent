rule socat_override: override {
  meta:
    description                   = "usr/bin/socat1"
    SEKOIA_Hacktool_Socat_Strings = "high"

  strings:
    $socat1 = "socat by Gerhard Rieger and contributors - see www.dest-unreach.org"
    $socat2 = "/tmp/socat-bind.XXXXXX"
    $socat3 = "copyright_socat"
    $socat4 = "socat_"

  condition:
    all of them
}
