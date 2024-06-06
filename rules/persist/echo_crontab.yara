rule echo_crontab : high {
	strings:
		$echo = /echo.{0,10}\* \* \* \*.{0,24}cron[\w\/ \-]{0,16}/
	condition:
		$echo
}