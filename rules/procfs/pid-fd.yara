rule proc_fd : suspicious {
	meta:
		description = "accesses file descriptors of other processes"
		ref = "https://s.tencent.com/research/report/1219.html"
	strings:
		$ref = /\/proc\/[%{$][\w\}]{0,12}\/fd/ 
		// https://github.com/ClickHouse/ClickHouse/blob/7022adefb0356b86e91a3dc139446e9909ce0130/src/Common/getCurrentProcessFDCount.cpp#L19
		$not_dev_fd = "/dev/fd"
	condition:
		$ref and none of ($not*)
}
