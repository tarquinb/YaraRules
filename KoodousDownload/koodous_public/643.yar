import "androguard"

rule fakeav
{

	condition:
	  androguard.package_name("com.hao.sanquanweishi") or
	  androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
}