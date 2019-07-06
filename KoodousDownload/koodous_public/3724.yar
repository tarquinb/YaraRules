rule Banks_Strings_PermanentTSB {

	strings:
		$string_1 = /permanenttsb\.ie/
		$string_2 = /open24\.ie/
	condition:
		1 of ($string_*)
}