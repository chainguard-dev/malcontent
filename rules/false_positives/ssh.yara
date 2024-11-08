rule sshd: override {
  meta:
    description   = "sshd"
    login_records = "medium"
    id_rsa        = "low"

  strings:
    $auth    = "SSH_USER_AUTH"
    $askpass = "SSH_ASKPASS"

  condition:
    any of them
}
