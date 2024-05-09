rule gnome_keyring_daemon : medium {
  strings:
	$ref = "gnome-keyring-da"
  condition:
	$ref
}
