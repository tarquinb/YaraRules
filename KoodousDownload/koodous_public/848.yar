import "androguard"

rule taskhijack4 : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "allowTaskReparenting"
	condition:
		
		$a 
		
}