<?php 

$myXmlData = file_get_contents("php://input");

$data = simplexml_load_string($myXmlData,null, LIBXML_NOENT) or die("Cant create object");

echo $data -> username,'\n';
echo $data -> email,'\n';
echo $data -> instagram,'\n';

?>

<!-- curl localhost:8000/xml.php -H "content-type: application/xml" -d "$(cat ./data.xml)" -->