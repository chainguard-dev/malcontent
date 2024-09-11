
rule muser_blacklist : critical {
  meta:
    description = "avoids execution if user has a particular name"
	ref = "https://www.zscaler.com/blogs/security-research/technical-analysis-bandit-stealer"
  strings:
	$ = "3u2v9m8" fullword
	$ = "8Nl0ColNQ5bq" fullword
	$ = "8VizSM" fullword
	$ = "Abby" fullword
	$ = "BvJChRPnsxn" fullword
	$ = "Frank" fullword
	$ = "HEUeRzl" fullword
	$ = "Harry Johnson" fullword
	$ = "John" fullword
	$ = "Julia" fullword
	$ = "Lisa" fullword
	$ = "Louise" fullword
	$ = "Lucas" fullword
	$ = "PateX" fullword
	$ = "PqONjHVwexsS" fullword
	$ = "PxmdUOpVyx" fullword
	$ = "RDhJ0CNFevzX" fullword
	$ = "RGzcBUyrznReg" fullword
	$ = "SqgFOf3G" fullword
	$ = "User01" fullword
	$ = "WDAGUtilityAccount" fullword
	$ = "fred" fullword
	$ = "george" fullword
	$ = "h7dk1xPr" fullword
	$ = "hmarc" fullword
	$ = "kEecfMwgj" fullword
	$ = "lmVwjj9b" fullword
	$ = "mike" fullword
	$ = "patex" fullword
	$ = "server" fullword
	$ = "test" fullword
	$ = "w0fjuOVmCcP5A" fullword
  condition:
   8 of them
}
