import "androguard"
import "file"
import "cuckoo"

rule SMSTrojan
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects Kasandra"
		
	strings:
		$a2 = "SMS_DELIVERED"
		$a3 = "SMS_SEND"
		$a4 = "RECEIVE_SMS"
		$a5 = "WRITE_SMS"
		
	condition:
		all of them
		
}