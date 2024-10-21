rule misp_mdjson : override {
  meta:
    description = "misp_sample.mdjson.log"
    lvt = "medium"
  strings:
    $attribute = "Attribute"
    $event = "Event"
    $galaxy = "Galaxy"
    $shadow = "ShadowAttribute"
  condition:
    all of them
}
