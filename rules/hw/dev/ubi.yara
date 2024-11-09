rule ubi: high linux {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw unsorted block images (UBI)"

  strings:
    $val = /\/dev\/ubi[\$%\w\{\}]{0,16}/

  condition:
    any of them
}

rule expected_ubi_users : override {
	meta:
		ubi = "medium"
	strings:
		$libuboot = "libuboot"
		$usage = "Usage:"
		$ubi = "ubifs" fullword
	condition:
		filesize < 120KB and any of them
}