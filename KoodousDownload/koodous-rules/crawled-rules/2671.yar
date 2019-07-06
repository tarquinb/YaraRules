
import "androguard"


rule SMS_Skunk

{

    condition:

        androguard.package_name(/org.skunk/) and

        androguard.permission(/SEND_SMS/)


}