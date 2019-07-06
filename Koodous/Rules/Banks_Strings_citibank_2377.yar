rule Banks_Strings_citibank {

	strings:
		$string_1 = /citibank\.com/
	condition:
		1 of ($string_*)
		
}