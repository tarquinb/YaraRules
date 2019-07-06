rule BANKBOT : malware
{
	meta:
		date = "2018-01-19"

	strings:
		$a = {2f 70 72 69 76 61 74 65 2f 74 75 6b 5f 74 75 6b 2e 70 68 70}

	condition:
		all of them
}