rule hidden_crontab : critical {
	meta:
		description = "persists via a hidden crontab entry"
	strings:
		$crontab = "crontab"

		$c_periodic_with_user = /\*[\/\d]{0,3} \* \* \* \* [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
		$c_periodic = /\*[\/\d]{0,3} \* \* \* \* [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
		$c_nickname_with_user = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
		$c_nickname = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
	condition:
		$crontab and any of ($c_*)
}
