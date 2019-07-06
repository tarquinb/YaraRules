rule Slempo
{
	meta:
		description = "Slempo"
		
	strings:
		$a = "org/slempo/service/Main" nocase
		$b = "org/slempo/service/activities/Cards" nocase
		$c = "org/slempo/service/activities/CvcPopup" nocase
		$d = "org/slempo/service/activities/CommonHTML" nocase

	condition:
		$a and ($b or $c or $d)
		
}