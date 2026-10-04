rule scapy_ldaphero: override {
  meta:
    description = "scapy/modules/ldaphero.py"
    sshdoor     = "low"

  strings:
    $header = /LDAP Hero: a LDAP browser based on the Scapy LDAP client/
    $class  = /LDAP Hero - LDAP GUI browser over Scapy's LDAP_Client/
    $import = /from scapy\.layers\.ldap import \(/

  condition:
    filesize < 96KB and all of them
}
