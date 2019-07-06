rule Banks_Strings_bancosantander {

	strings:
		$string_1 = /bancosantander\.es/
	condition:
		1 of ($string_*)
		
}