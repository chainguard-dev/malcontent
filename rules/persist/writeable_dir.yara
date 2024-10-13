rule world_writeable_dirs : high {
  meta:
    description = "mentions multiple world writeable directories"
  strings:
	$tmp_tmp = /\/tmp[\w\.\/]{0,32}/ fullword
	$tmp_dev_shm = /\/dev\/shm[\w\.\/]{0,32}/
	$tmp_dev_mqueue = /\/dev\/mqueue[\w\.\/]{0,32}/
	$tmp_var_tmp = /\/var\/tmp[\w\.\/]{0,32}/
  condition:
	3 of them
}
