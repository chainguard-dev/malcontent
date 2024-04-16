
rule uac_bypass : suspicious {
  meta:
    description = "may bypass UAC (User Account Control)"
  strings:
	$uacbypass = "uacbypass" fullword
	$delegate = "fodhelper" fullword
  condition:
	any of them
}
