rule Banks_Strings_lacaixa {

	strings:
		$string_1 = /lacaixa\.es/
	condition:
		1 of ($string_*)
}