rule gcloud_mysql_py: override {
  meta:
    description      = "mysql.py"
    infection_killer = "medium"

  strings:
    $description = "This installer will install mysql-server on an Ubuntu machine."
    $install     = "apt-get -y install mysql-server"
    $license     = "# Copyright (c) 2006-2009 Mitch Garnaat http://garnaat.org/"

  condition:
    filesize < 10KB and all of them
}
