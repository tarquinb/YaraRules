import "androguard"
import "file"
import "cuckoo"


rule smssender_FakeAPP
{

	condition:
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD") or 
		androguard.package_name("test.app") or 
		androguard.receiver("b93478b8cdba429894e2a63b70766f91.ads.Receiver")
}


rule SMSFraud
{
	condition:
		androguard.certificate.sha1("003274316DF850853687A26FCA9569A916D226A0") or 
		androguard.package_name("com.googleapi.cover") or 
		androguard.package_name("ru.android.apps")

}