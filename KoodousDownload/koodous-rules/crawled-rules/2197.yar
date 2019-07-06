
import "androguard"

import "file"

import "cuckoo"



rule koodous : official

{


    strings:

        $droidplugin = "droidplugin"

    condition:

        $droidplugin


}