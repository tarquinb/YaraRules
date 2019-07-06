import "androguard"

rule taskhijack3 : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "taskAffinity"
	condition:
		
		$a 
		
}