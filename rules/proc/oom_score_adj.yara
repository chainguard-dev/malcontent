
rule oom_score_adj {
	meta:
		capability = "CAP_SYS_RESOURCE"
		description = "Accesses OOM (out-of-memory) repear settings"
	strings:
		$ref = "oom_score_adj" fullword
	condition:
		any of them
}
