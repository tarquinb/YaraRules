import "androguard"

rule fraudulent:numeric_developers
{
	meta:
		koodous_search = "developer:91"
		koodous_search2 = "developer:86"
		koodous_search3 = "developer:34"

	condition:
		androguard.certificate.sha1("7D4EA444984A1AD84BBE408DB4A57A42B989E51A") or //developer 91
		androguard.certificate.sha1("78739E2E80F74715D31A72185942487216E40D81") or //developer 86
		androguard.certificate.sha1("E08260D36C0E5E2CEB9DE2FB0BAB0ABEA1471058") //developer 34
		
}