rule third_party_corpus: override {
  meta:
    description             = "third-party rule corpus"
    ESET_Keydnap_Downloader = "harmless"
    Jupyter                 = "harmless"
    php_eval_base64_decode  = "harmless"

  strings:
    // corpus anchor strings (hex-encoded)
    $a = { 43 4C 45 41 56 45 5F 54 52 41 49 54 53 5F 44 49 52 }  // suppress: text_as_hex
    $b = { 63 6C 65 61 76 65 3A 3A 63 6F 6E 74 65 78 74 }  // suppress: text_as_hex

  condition:
    filesize < 150MB and all of them
}
