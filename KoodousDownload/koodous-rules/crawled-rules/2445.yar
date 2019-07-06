
import "androguard"

import "file"

import "cuckoo"



rule Marcher_new

{

    meta:

        description = "This rule detects new Marcher variant with device admin notification screen"

        sample = "b956e12475f9cd749ef3af7f36cab8b20c5c3ae25a13fa0f4927963da9b9256f"


    strings:

        $a = "res/xml/device_admin_new.xml"



    condition:

        $a


}