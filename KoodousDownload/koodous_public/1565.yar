rule GCM
{
	meta:
		description = "Trojan-SMS AndroidOS GCM"
		sample = "81BB2E0AF861C02EEAD41FFD1F08A85D9490FE158586FA8509A0527BD5835B30"

	strings:
		$a = "whatisthefuckingshirtmazafakayoyonigacomon.ru"

	condition:
		all of them
		
		
}