
import "androguard"


rule dialer

{

    meta:

        description = "Android Dialers"

        sample = "6f29c708a24f1161d56ca36a5601909efac0087ffe4033ad87153e268ff52b06"


    strings:

        $a = {6C 6C 61 6D 61 64 61 5F 72 65 61 6C 69 7A 61 64 61}


    condition:

        $a and

        androguard.activity(/com\.phonegap\.proy/) and

        androguard.activity(/com\.keyes\.youtube/) and

        androguard.activity(/com\.phonegap\.plugins/) and 

        androguard.permission(/android\.permission\.CALL_PHONE/) 

}