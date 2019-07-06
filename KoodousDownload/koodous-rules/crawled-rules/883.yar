
import "androguard"



rule sending2smtp

{

    meta:

        description = "Connects with remote chinese servers"


    strings:

        $a = "18201570457@163.com"

        $b = "smtp.163.com"


    condition:

        $a and $b


}