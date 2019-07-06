import "androguard"


rule tinhvan
{
	meta:
		sample = "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"

	condition:
		androguard.certificate.sha1("0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5")
		
}