
import "androguard"

import "file"

import "cuckoo"



rule Generic : Banker

{

    meta:

        description = "Generic Rule to identify banker trojans"


    strings:

        $gp = "Google Play" nocase


        $mastercard_1 = "cvc_mastercard" nocase

        $mastercard_2 = "mastercard_cvc" nocase


        $visa_1 = "cvc_visa" nocase

        $visa_2 = "visa_cvc" nocase


        $amex_1 = "cvc_amex" nocase

        $amex_2 = "amex_cvc" nocase


    condition:

        $gp and 

        (

            (1 of ($mastercard_*)) or 

            (1 of ($visa_*)) or 

            (1 of ($amex_*))

        ) and

        androguard.permission(/android.permission.RECEIVE_SMS/) and

        androguard.permission(/android.permission.READ_SMS/) and

        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)  

}