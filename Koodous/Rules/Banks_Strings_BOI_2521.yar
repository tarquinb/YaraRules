rule Banks_Strings_BOI {

	strings:
		$string_1 = /boi\.com/
		$string_2 = /365online\.com/
		$string_3 = /businessonline\-boi\.com/
		$string_4 = /bankofireland\.com/
	condition:
		1 of ($string_*)
}