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
