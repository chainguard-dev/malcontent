rule lkm_dirent {
	strings:
		$dirent = "linux_dirent"
		$Linux = "Linux"
	condition:
		all of them
}
