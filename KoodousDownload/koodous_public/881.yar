import "androguard"

rule FakeClashOfClans
{
	meta:
		description = "Fake Clash of clans applications"

	condition:
		androguard.app_name(/clash of clans/i) and
		not androguard.certificate.sha1("456120D30CDA8720255B60D0324C7D154307F525")
}