
import "androguard"

import "file"

import "cuckoo"



rule koodous : official

{

    meta:

        description = "This rule detects sample that mess around with the sensitive system/priv-app path (for payload dropping etc)"



    strings:

        $certs_path = "etc/security/cacerts"


    condition:

        $certs_path


}