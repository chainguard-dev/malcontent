rule redpanda_connect: override {
  meta:
    description               = "/usr/bin/redpanda-connect"
    malware_CobaltStrike_v3v4 = "harmless"

  strings:
    $go_module = "github.com/redpanda-data/connect/v4"
    $go_pkg    = "github.com/redpanda-data/benthos/v4"

  condition:
    filesize > 200MB and filesize < 500MB and all of them
}
