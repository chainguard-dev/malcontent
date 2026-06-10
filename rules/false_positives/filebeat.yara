rule misp_mdjson: override {
  meta:
    description  = "misp_sample.mdjson.log"
    pastebin     = "low"
    rootkit_high = "low"

  strings:
    $attribute = "Attribute"
    $event     = "Event"
    $galaxy    = "Galaxy"
    $shadow    = "ShadowAttribute"

  condition:
    filesize < 128KB and all of them
}

rule filebeat: override {
  meta:
    description            = "/usr/bin/filebeat - Elastic Beats log shipper"
    BlackTech_TSCookie_elf = "harmless"

  strings:
    $beats_module = "github.com/elastic/beats/v7"
    $filebeat     = "github.com/elastic/beats/v7/x-pack/filebeat"

  condition:
    filesize < 300MB and all of them
}
