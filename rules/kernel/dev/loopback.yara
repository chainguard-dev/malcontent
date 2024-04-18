rule dev_loopback : notable {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "access virtual block devices (loopback)"
	strings:
		$val = /\/dev\/loop[\$%\w\{\}]{0,16}/
	condition:
		any of them
}
