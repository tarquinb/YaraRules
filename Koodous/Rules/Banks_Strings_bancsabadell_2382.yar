rule Banks_Strings_bancsabadell {

	strings:
		$string_1 = /bancsabadell\.com/
	condition:
		1 of ($string_*)
}