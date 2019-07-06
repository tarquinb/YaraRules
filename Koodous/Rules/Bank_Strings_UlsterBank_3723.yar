rule Banks_Strings_UlsterBank {

	strings:
		$string_1 = /digital\.ulsterbank\.ie/
		$string_2 = /ulsterbankanytimebanking\.ie/
		$string_3 = /ulsterbank\.ie/
		$string_4 = /cardsonline\-commercial\.com/
		$string_5 = /bankline\.ulsterbank\.ie/
	condition:
		1 of ($string_*)
}