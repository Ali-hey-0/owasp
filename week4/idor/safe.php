<?php 

public function destroyAddress($id,Request $request)
    {
        $address = Address::where('id',$id) -> where('user_id',\auth() ->user()->id)->first();
        if($address){
            $address->delete();
            return helpers::preparedJsonResponseWithMessage(true,'the address has been deleted successfully');
        }
    }


?>