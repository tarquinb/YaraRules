rule koodous : official
{
	meta:
		description = "Triada token(https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/)"
		sample = "0cc9bcf8ae60a65f913ace40fd83648e"

	strings:
		$a = {63 6f 6e 66 69 67 6f 70 62}

	condition:
		$a
		
}