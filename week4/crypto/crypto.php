<?php 

echo md5("Ali");

echo base64_encode("Ali");

echo shell_exec('echo -n "Ali" | openssl enc -aes-256-cbc -a -k 123');

?>

<!-- 7a9b46ab6d983a85dd4d9a1aa64a3945QWxp*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
U2FsdGVkX19QWUFbo6+gH6WEnaJCZO17qeGoRXuaDyQ= -->