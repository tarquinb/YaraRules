
import "androguard"

import "file"

import "cuckoo"



rule XavierCampaign

{

    meta:

        description = "This rule detects samples from the Xavier campaign"

        sample = "8a72124709dd0cd555f01effcbb42078"

        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/analyzing-xavier-information-stealing-ad-library-android/"


    condition:

        androguard.service(/xavier.lib.message/) and 

        androguard.receiver(/xavier.lib.Xavier/)


}