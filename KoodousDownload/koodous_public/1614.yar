import "androguard"
import "file"
import "cuckoo"


rule Spy_Banker
{
	meta:
		description = "This rule detects the Spy.Banker.BQ"
		sample = "d715e0be04f97bb7679dec413ac068d75d0c79ce35c3f8fa4677fc95cefbfeb8"

	strings:
		$a = "#BEBEBE"
		$b = "Remove MMS"
		$c = "Enter credit card"
		$d = "SELECT  * FROM smsbase"
		$e = "szCardNumverCard"
		$f = "[admintext]"
		
	condition:
		all of them
		
}