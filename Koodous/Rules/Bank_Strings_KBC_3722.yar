rule Banks_Strings_KBC {

	strings:
		$string_1 = /online\.kbc\.ie/
		$string_2 = /kbc\.ie/
	condition:
		1 of ($string_*)
}