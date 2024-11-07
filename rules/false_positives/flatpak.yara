rule flatpak: override {
  meta:
    description = "flatpak"
    lvt_locker  = "medium"

  strings:
    $flatpak = "FLATPAK_BINARY" fullword

  condition:
    filesize < 3MB and any of them
}
