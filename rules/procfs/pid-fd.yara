rule proc_fd : suspicious {
	meta:
		description = "accesses file descriptors of other processes"
		ref = "https://s.tencent.com/research/report/1219.html"
	strings:
		$string = /\/proc\/[%{$][\w\}]{0,12}\/fd/ 
	condition:
		any of them
}
