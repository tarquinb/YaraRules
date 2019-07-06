
import "androguard"

import "file"

import "cuckoo"



rule DirtyGirl

{

    meta:

        description = "This rule detects dirtygirl samples"

        sample = "aeed925b03d24b85700336d4882aeacc"


    condition:

        androguard.service(/com\.door\.pay\.sdk\.sms\.SmsService/) or

        androguard.url(/120\.26\.106\.206/)


}