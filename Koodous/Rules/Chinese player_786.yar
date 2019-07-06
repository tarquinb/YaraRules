import "androguard"

rule chineseporn: player
{
	meta:
		sample = "4a29091b7e342958d9df00c8a37d58dfab2edbc06b05e07dcc105750f0a46c0f"

	condition:
		androguard.package_name("com.mbsp.player") and
		androguard.certificate.issuer(/O=localhost/)
		
}