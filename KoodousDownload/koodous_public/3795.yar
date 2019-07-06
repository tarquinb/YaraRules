import "androguard"

rule SMSLocker
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects Kasandra"
		
	strings:
		$a1 = "flushCommands"
		$a2 = "httpPost"
		$a3 = "httpGet"
		$a4 = "lockScreen"
	condition:
		all of them
		
}