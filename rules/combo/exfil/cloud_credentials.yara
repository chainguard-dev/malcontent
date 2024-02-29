rule multiple_cloud_credentials {
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
