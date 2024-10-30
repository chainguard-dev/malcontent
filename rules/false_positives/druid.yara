rule wikiticker: override {
  meta:
    description                = "wikiticker-2015-09-12-sampled.json"
    crypto_stealer_names       = "medium"
    common_username_block_list = "medium"

  strings:
    $channel   = /#.{2}.wikipedia/
    $wikipedia = /https:\/\/.{2}.wikipedia.org/

  condition:
    filesize < 20MB and all of them
}
