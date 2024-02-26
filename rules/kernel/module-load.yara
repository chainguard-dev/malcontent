rule init_module {
	meta:
		description = "Load Linux kernel module"
		syscall = "init_module"
		capability = "CAP_SYS_MODULE"
	strings:
		$ref = "init_module" fullword
	condition:
		all of them
}

rule kernel_module_loader {
  meta:
    hash_2023_installer_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $insmod = /insmod [ \w\.\/_-]{1,32}\.ko/
  condition:
    all of them
}