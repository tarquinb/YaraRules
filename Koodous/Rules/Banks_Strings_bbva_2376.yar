rule Banks_Strings_bbva {

	strings:
		$string_1 = /bbva\.es/
		$string_2 = /bbvanetcash\.com/
	condition:
		1 of ($string_*)
		
}