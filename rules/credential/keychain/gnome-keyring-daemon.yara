rule gnome_keyring_daemon: medium {
  meta:

  strings:
    $ref = "gnome-keyring-da"

  condition:
    $ref
}
