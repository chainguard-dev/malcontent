rule unusual_cd_val : suspicious {
	meta:
		description = "changes to an unusual system directory"
	strings:
		$d_dev_mqueue = "cd /dev/mqueue"
		$d_dev_shm = "cd /dev/shm"
		$d_mnt = "cd /mnt"
		$d_root = "cd /root"
		$d_tmp = "cd /tmp"
		$d_usr = "cd /usr"
		$d_var_log = "cd /var/log"
		$d_var_run = "cd /var/run"
		$d_var_tmp = "cd /var/tmp"
	condition:
		any of them
}

rule unusual_cd_dev_val : suspicious {
	meta:
		description = "changes to an unusual system directory"
	strings:
		$d_dev = /cd \/dev[\w\/\.]{0,64}/
		$makedev = "MAKEDEV"
	condition:
		$d_dev and not $makedev
}
