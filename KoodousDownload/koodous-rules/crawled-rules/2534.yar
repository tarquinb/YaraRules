
import "androguard"


rule SMS_Fraud

{

    meta:

        Author = "https://www.twitter.com/SadFud75"

    condition:

        androguard.package_name("com.sms.tract") or androguard.package_name("com.system.sms.demo") or androguard.package_name(/com\.maopake/)

}