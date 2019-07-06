import "androguard"

rule otherFindSMS
{
    strings:
        $text_string = "sendsms"

    condition:
       ($text_string or androguard.permission(/SEND_SMS/))
	   and androguard.permission(/FLASHLIGHT/)
}