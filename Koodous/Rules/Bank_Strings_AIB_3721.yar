rule Banks_Strings_AIB {

	strings:
		$string_1 = /onlinebanking\.aib\.ie/
		$string_2 = /business\.aib\.ie/
		$string_3 = /aib\.ie/
	condition:
		1 of ($string_*)
}