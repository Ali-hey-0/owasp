<?php 

class Fruit{
    public $name;
    public $color;

    function set_name($name){
        $this-> name = $name;
    }
    function get_name(){
        return $this->name;
    }
}

$apple = new Fruit();
$banana = new Fruit();

$apple ->set_name("Apple");
$banana ->set_name("Banana");


echo "\n";
echo $apple->get_name();
echo "\n";
echo $banana->get_name();
echo "\n\n";

?>