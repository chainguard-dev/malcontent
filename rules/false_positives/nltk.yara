rule nltk_test_pathsec: override {
  meta:
    description                         = "nltk/test/unit/test_pathsec.py"
    ELCEEF_Obfuscated_IP_Address_In_URL = "harmless"

  strings:
    $test_pathsec    = "test_pathsec"
    $nltk_pathsec    = "nltk.pathsec"
    $nltk_downloader = "nltk.downloader"

  condition:
    filesize < 64KB and all of them
}
