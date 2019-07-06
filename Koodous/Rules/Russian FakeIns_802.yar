import "androguard"


rule fakeInstaller
{
	meta:
		description = "The apps developed by this guy are fakeinstallers"
		one_sample = "fb20c78f51eb781d7cce77f501ee406a37327145cf43667f8dc4a9d77599a74d"

	condition:
		androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
		
}