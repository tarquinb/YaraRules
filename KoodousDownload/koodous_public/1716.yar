import "androguard"

rule pokemongo : fake
{
	meta:
		description = "This rule detects fakes Pokemon Go apps "
		sample = ""

	condition:
		(androguard.package_name("com.nianticlabs.pokemongo") or androguard.app_name("Pokemon GO")) and not
		androguard.certificate.sha1("321187995BC7CDC2B5FC91B11A96E2BAA8602C62")
		
}