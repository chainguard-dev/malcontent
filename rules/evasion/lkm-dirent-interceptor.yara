rule lkm {
	strings:
		$dirent = "linux_dirent"
		$Linux = "Linux"
	condition:
		all of them
}
