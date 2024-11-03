rule multiple_cloud_credentials: high {
  meta:
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi            = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_enumeration_linpeas       = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $s_access_tokens_db  = "access_tokens.db"
    $s_config_gcloud     = ".config/gcloud"
    $s_accounts_xml      = "accounts.xml"
    $s_authinfo2         = "authinfo2"
    $s_azure_json        = "azure.json"
    $s_boto              = ".boto"
    $s_censys_cfg        = "censys.cfg"
    $s_credentials_db    = "credentials.db"
    $s_filezilla_xml     = "filezilla.xml"
    $s_git_credentials   = ".git-credentials"
    $s_kube_env          = "kube-env"
    $s_netrc             = ".netrc"
    $s_ngrok_yml         = "ngrok.yml"
    $s_passwd_s3fs       = ".passwd-s3fs"
    $s_pgpass            = ".pgpass"
    $s_queue_sqlite3     = "queue.sqlite3"
    $s_recentservers_xml = "recentservers.xml"
    $s_s3b_config        = ".s3b_config"
    $s_s3backer_passwd   = ".s3backer_passwd"
    $s_s3cfg             = ".s3cfg"
    $s_s3proxy_conf      = "s3proxy.conf"
    $s_samba_credentials = ".samba_credentials"
    $s_servlist_conf     = "servlist.conf"
    $s_smbclient_conf    = ".smbclient.conf"
    $s_smbcredentials    = ".smbcredentials"
    $s_adc               = "application_default_credentials.json"

  condition:
    filesize < 20MB and 5 of them
}
