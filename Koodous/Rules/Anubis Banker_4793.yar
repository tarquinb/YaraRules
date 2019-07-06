import "androguard"

rule Anubis
{
	meta:
    	description = "Rule set for detect Anubis banker"
    	sample = "0ce93cabedaccdc9c2f4752df7359002e3735e772afd48d94689aff80bcb7685"

    strings:
        $string_1= "ad"
        $string_2= "dL"
        $string_3= "ik"
        $string_4= "el"
        $string_5= "yS"
        $string_6= "ub"
        $string_7= "ta"
        $string_8= "us"
        $string_24= "po"
        $string_32= "si"
        $string_40= "ti"
        $string_48= "ve"
        $string_64= "al"
        $string_72= "ue"
        $string_88= "in"
        $string_104= "ap"
        $string_112= "ac"
        $string_120= "it"
    
    condition:
         all of ($string_*) and
         androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and
         androguard.permissions_number == 19 and
         androguard.permission(/ACCESS_FINE_LOCATION/) and
         androguard.permission(/SEND_SMS/) and
         androguard.permission(/READ_EXTERNAL_STORAGE/) and
         androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
         androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
         androguard.permission(/READ_CONTACTS/) and
         androguard.permission(/READ_PHONE_STATE/) and
         androguard.permission(/SYSTEM_ALERT_WINDOW/) and
         androguard.permission(/WRITE_SMS/) and
         androguard.permission(/ACCESS_NETWORK_STATE/) and
         androguard.permission(/RECORD_AUDIO/) and
         androguard.permission(/WAKE_LOCK/) and
         androguard.permission(/GET_TASKS/) and
         androguard.permission(/CALL_PHONE/) and
         androguard.permission(/RECEIVE_SMS/) and
         androguard.permission(/INTERNET/) and
         androguard.permission(/PACKAGE_USAGE_STATS/) and
         androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
         androguard.permission(/READ_SMS/)
}