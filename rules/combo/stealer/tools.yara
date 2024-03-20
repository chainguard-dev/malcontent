rule executable_calls_archive_tool : notable {
  meta:
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2020_Macma_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
    hash_2019_Macma_AgentB = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
    hash_2021_Macma_CDDS_UserAgent = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
    hash_2011_bin_fxagent = "737bb6fe9a7ad5adcd22c8c9e140166544fa0c573fe5034dfccc0dc237555c83"
    hash_2021_CDDS_installer_v2021 = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
    $a_tar_c = "tar -c"
    $a_tar_xf = "tar xf"
    $a_tar_cf = "tar cf"
    $a_tar_rX = "tar -r -X"
    $a_tar_T = "tar -T"
    $a_zip_x = "zip -X"
    $a_zip_r = "zip -r"
	$a_ditto = /ditto -[\w\-\/ ]{0,32}/
    $not_applet = "zip -r ../applet.zip"
    $not_usage = "Usage:"
  condition:
    any of ($a*) and none of ($not*)
}
