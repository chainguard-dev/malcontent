rule unusual_cd_val : suspicious {
	meta:
		description = "changes to an unusual system directory"
	strings:
		$dev = "cd /dev"
		$dev_mqueue = "cd /dev/mqueue"
		$dev_shm = "cd /dev/shm"
		$mnt = "cd /mnt"
		$root = "cd /root"
		$tmp = "cd /tmp"
		$usr = "cd /usr"
		$var_log = "cd /var/log"
		$var_run = "cd /var/run"
		$var_tmp = "cd /var/tmp"
	condition:
		any of them
}
