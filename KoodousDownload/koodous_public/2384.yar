rule Banks_Strings_caixabank {

	strings:
		$string_1 = /caixabank\.es/
	condition:
		1 of ($string_*)
}