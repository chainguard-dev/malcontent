rule adminer_php: override {
  meta:
    description          = "adminer.php - legitimate database management tool"
    webshell_adminer_4_7 = "harmless"

  strings:
    $adminer_header = "Adminer - Compact database management"
    $adminer_org    = "https://www.adminer.org/"
    $adminer_author = "Jakub Vrana"

  condition:
    filesize < 1MB and all of them
}
