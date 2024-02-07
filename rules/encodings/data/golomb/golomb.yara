
rule golumb_vlc {
	strings:
		$golomb_vlc = "golomb_vlc"
	condition:
		any of them
}
