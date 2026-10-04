rule bookstack_system_cli: override {
  meta:
    description                             = "/app/www/bookstack-system-cli phar"
    SIGNATURE_BASE_WEBSHELL_PHP_Dynamic_Big = "harmless"

  strings:
    $phar_start      = /const START = 'run\.php';/
    $artisan_runner  = /src\/Services\/ArtisanRunner\.php/
    $app_locator     = /src\/Services\/AppLocator\.php/
    $mysql_runner    = /src\/Services\/MySqlRunner\.php/
    $backup_command  = /src\/Commands\/BackupCommand\.php/
    $restore_command = /src\/Commands\/RestoreCommand\.php/

  condition:
    filesize < 512KB and all of them
}
