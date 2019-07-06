
import "androguard"

import "file"

import "cuckoo"



rule sms_kotlin

{

    meta:

        description = "This rule detects an SMS subscription related samples created from Kotlin language "

        sample = "d50e0523db467cf821df7ce3d8c0dc75"


    strings:

        $a_1 = "52.76.80.41"


    condition:

        $a_1 and

        androguard.service(/FlowService/)



}