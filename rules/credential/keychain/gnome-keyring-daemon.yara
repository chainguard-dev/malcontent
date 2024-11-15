rule gnome_keyring_daemon: medium {
  meta:
    description = "references the gnome-keyring-daemon"

  strings:
    $ref = /gnome-keyring-da[a-z\-]{0,8}/

  condition:
    $ref
}
