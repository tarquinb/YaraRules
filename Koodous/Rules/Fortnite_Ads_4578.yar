import "androguard"


rule Type1
{
	meta:
		description = "This rule detects false Fortnite APKs"
		sample = "9daef278e769ea63300ac58b74ca626daa092c2816caf441dbe7119f2925aeea/analysis"


	condition:
		androguard.app_name(/Fortnite/) and
		
		androguard.url("http://smarturl.it/3lrizx") or
		androguard.url("https://www.fileoasis.net/cl.php?id=ce226a76bbef5126f4f531b5c3fa595a")
		
}