import "androguard"

rule FakeGooglePlay
{
	meta:
		description = "Fake Google Play applications"

	condition:
		androguard.app_name(/google play/i) and
		not androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788")
}