
import "androguard"

import "file"

import "cuckoo"



rule koodous : official

{

    meta:

        description = "This rule detects banking services phonenumbers hardcoded in apk"


    strings:


        $str15999999  =   "15999999"

        $str15991111  =   "15991111"

        $str15442100  =   "15442100"

        $str15882100  =   "15882100"

        $str80055550  =   "80055550"

        $str15881599  =   "15881599"

        $str15889999  =   "15889999"

        $str15448000  =   "15448000"

        $str15778000  =   "15778000"

        $str15998000  =   "15998000"



    condition:

        1 of them 


}