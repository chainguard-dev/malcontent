rule flatpak: override {
  meta:
    description = "flatpak"
    hidden_x11  = "medium"

  strings:
    $flatpak = "FLATPAK_BINARY" fullword

  condition:
    filesize < 3MB and any of them
}
