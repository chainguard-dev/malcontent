rule gnome_keyring_daemon : notable {
  strings:
	$ref = "gnome-keyring-da"
  condition:
	$ref
}
