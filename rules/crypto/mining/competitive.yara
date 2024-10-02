
rule killer_miner_panchansminingisland : critical {
  meta:
    description = "crypto miner virus"
	filetypes = "elf"
  strings:
    $ = "killer"
	$ = "miner"
	$ = "p2p"
	$ = "protector"
	$ = "rootkit"
	$ = "spreader"
	$ = "updater"
  condition:
	filesize < 120MB and 6 of them
}
