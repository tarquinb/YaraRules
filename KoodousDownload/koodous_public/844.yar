import "androguard"

rule taskhijack2 : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "TaskStackBuilder"
	condition:
		
		$a 
		
}