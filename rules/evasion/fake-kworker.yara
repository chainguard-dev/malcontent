rule fake_kworker : critical {
  meta:
	description = "Pretends to be a kworker kernel thread"
  strings:
	$kworker = /\[{0,1}kworker\/[\d:\]]{1,5}/
	$kworker2 = "kworker" fullword
  condition:
	any of them
}