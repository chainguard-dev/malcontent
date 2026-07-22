rule coder_remote_dev: override {
  meta:
    description             = "/usr/bin/coder - Coder cloud development environment platform"
    systemctl_botnet_client = "low"
    suspected_data_stealer  = "low"
    wordpress_xmlrpc        = "low"

  strings:
    $go_module = "github.com/coder/coder/v2"
    $go_cmd    = "coder/coder/v2/cmd/coder"

  condition:
    filesize > 100MB and filesize < 600MB and all of them
}
