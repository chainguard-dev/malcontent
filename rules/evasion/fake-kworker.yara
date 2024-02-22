rule fake_kworker : critical {
  meta:
	description = "Pretends to be a kworker kernel thread"
  strings:
	$kworker = /\[*kworker[\/\d:\]]{0,5}/
  condition:
	$kworker
}