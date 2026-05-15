rule nltk_test_pathsec: override {
  meta:
    description                         = "nltk/test/unit/test_pathsec.py"
    ELCEEF_Obfuscated_IP_Address_In_URL = "harmless"

  strings:
    $ssrf_test       = "test_ssrf_ip_obfuscation"
    $nltk_pathsec    = "nltk.pathsec"
    $nltk_downloader = "nltk.downloader"

  condition:
    filesize < 64KB and all of them
}
