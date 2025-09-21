<?php 

class User{
    public $name;
    public $email;
    private $role;
    protected $active;

    function __construct($name, $email, $role){
        $this->name = $name;
        $this->email = $email;
        $this->role = $role;
        $this->active = true;
    }
}

$user = new User("ali", "ali@example.com", "admin");

echo base64_encode(serialize($user));

?>