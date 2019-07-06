rule Banks_Strings_banamex {

	strings:
		$string_1 = /banamex\.com/
	condition:
		1 of ($string_*)
}