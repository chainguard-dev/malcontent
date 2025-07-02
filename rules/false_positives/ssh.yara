rule ignore_sshd: override {
  meta:
    description = "sshd"
    id_rsa      = "low"
    sshd        = "low"

  strings:
    $auth    = "SSH_USER_AUTH"
    $askpass = "SSH_ASKPASS"

  condition:
    any of them
}
