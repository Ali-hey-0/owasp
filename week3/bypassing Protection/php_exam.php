<?php
function check_hmack($url,$hmack){
    return ($hmack == md5($url));
}

if(isset($_GET['url']) && isset($_GET['h'])){
    if(check_hmack($_GET['url'],$_GET['h']))header('Location: '.$_GET['url']);
    else echo "Invalid HMAC";
}

?>

<pre>
<a href="?url=https://google.com&h=99999ebcfdb78df077ad2727fd00969f">google.com</a>

<!-- curl -I "http://localhost:8000/?url=https://memoryleaks.ir&h=0b55264ae65f7f530842165eb646e6f4" #Redirects to memoryleaks.ir -->