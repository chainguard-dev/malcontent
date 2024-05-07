rule heartbeat : notable {
	meta:
		description = "references a 'heartbeat' - often used by background daemons"
	strings:
		$ref = /[\w \:]{0,32}[hH]eart[bB]eat[\w\: ]{0,8}/
	condition:
		any of ($ref*)
}
