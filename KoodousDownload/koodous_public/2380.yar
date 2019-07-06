rule Banks_Strings_bankia {

	strings:
		$string_1 = /bankia\.es/
	condition:
		1 of ($string_*)
}