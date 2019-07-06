import "androguard"

rule fake_installer: orggoogleapp
{
	condition:
		androguard.certificate.sha1("86718264E68A7A7C0F3FB6ECCB58BEC546B33E22")				
}