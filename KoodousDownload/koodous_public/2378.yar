rule Banks_Strings_scotiabank {

	strings:
		$string_1 = /scotiabank\.com/
	condition:
		1 of ($string_*)
		
}