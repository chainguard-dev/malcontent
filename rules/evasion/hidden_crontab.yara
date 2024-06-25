
rule hidden_crontab : critical {
  meta:
    description = "persists via a hidden crontab entry"
    hash_2024_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2024_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
    hash_2024_Chaos_27cd = "27cdb8d8f64ce395795fdbde10cf3a08e7b217c92b7af89cde22abbf951b9e99"
  strings:
    $crontab = "crontab"
    $c_periodic_with_user = /\*[\/\d]{0,3} \* \* \* \* [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_periodic = /\*[\/\d]{0,3} \* \* \* \* [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_nickname_with_user = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_nickname = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
  condition:
    $crontab and any of ($c_*)
}
