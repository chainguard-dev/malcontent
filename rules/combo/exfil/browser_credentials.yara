rule multiple_browser_credentials : suspicious {
  meta:
    hash_2023_stealer_hashbreaker = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $c_library_keychains = "/Library/Keychains"
    $c_cookies_sqlite = "cookies.sqlite"
    $c_moz_cookies = "moz_cookies"
    $c_opera_gx = "OperaGX"
    $c_keychain_db = "login.keychain-db"
    $c_dscl_local = "dscl /Local/Default"
    $c_osascript = "osascript"
    $c_find_generic_password = "find-generic-password"
    $not_security = "PROGRAM:security"
    $not_verbose = "system_verbose"
    $not_kandji = "com.kandji.profile.mdmprofile"
    $not_xul = "XUL_APP_FILE"
  condition:
    3 of ($c_*) and none of ($not_*)
}

rule multiple_browser_credentials_2 {
  meta:
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_stealer_hashbreaker = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2017_GoPhoto = "a4d8367dc2df3a8539b9baf8ee48d09f5a8e9f9d2d58431909de0bb0816464a0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $a_google_chrome = "Google/Chrome"
    $a_app_support = "Application Support"
    $a_app_support_slash = "Application\\ Support"
    $a_cookies_sqlite = "cookies.sqlite"
    $a_cookies = "Cookies"
    $a_places_sqlite = "places.sqlite"
    $a_moz_cookies = "moz_cookies"
    $a_firefox_profiles = "Firefox/Profiles"
    $a_opera_gx = "OperaGX"
    $a_form_history = "formhistory.sqlite"
    $a_chrome_local_state = "Chrome/Local State"
    $a_brave_software = "BraveSoftware"
    $a_opera = "Opera Software"
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    3 of ($a_*) and none of ($not_*)
}

rule multiple_cloud_credentials : suspicious {
  meta:
    hash_2023_QubitStrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Linux_Malware_Samples_efa8 = "efa875506296d77178884ba8ac68a8b6d6aef24e79025359cf5259669396e8dd"
    hash_2023_Linux_Malware_Samples_efac = "efacd163027d6db6009c7363eb2af62b588258789735352adcbc672cd412c7c1"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
  strings:
    $s_access_tokens_db = "access_tokens.db"
	$s_config_gcloud = ".config/gcloud"
	$s_gcloud = "gcloud"
    $s_accounts_xml = "accounts.xml"
    $s_api_key = "api_key"
    $s_authinfo2 = "authinfo2"
    $s_azure_json = "azure.json"
    $s_boto = ".boto"
    $s_censys_cfg = "censys.cfg"
    $s_credentials = "credentials" fullword
    $s_credentials_db = "credentials.db"
    $s_filezilla_xml = "filezilla.xml"
    $s_git_credentials = ".git-credentials"
    $s_kube_env = "kube-env"
    $s_netrc = ".netrc"
    $s_ngrok_yml = "ngrok.yml"
    $s_passwd_s3fs = ".passwd-s3fs"
    $s_pgpass = ".pgpass"
    $s_queue_sqlite3 = "queue.sqlite3"
    $s_recentservers_xml = "recentservers.xml"
    $s_s3b_config = ".s3b_config"
    $s_s3backer_passwd = ".s3backer_passwd"
    $s_s3cfg = ".s3cfg"
    $s_s3proxy_conf = "s3proxy.conf"
    $s_samba_credentials = ".samba_credentials"
    $s_secrets = "secrets" fullword
    $s_servlist_conf = "servlist.conf"
    $s_smbclient_conf = ".smbclient.conf"
    $s_smbcredentials = ".smbcredentials"
    $s_adc = "application_default_credentials.json"
  condition:
    4 of them
}
