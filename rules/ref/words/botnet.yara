rule bot : high {
  meta:
    description = "References a 'botnet'"
  strings:
    $ = "bot deployed"
	$ = "Botnet"
  condition:
    any of them
}
