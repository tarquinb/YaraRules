import "androguard"

rule HillClimbRacing
{
	meta:
		description = "This rule detects fake application of Hill Climb Racing"
		sample = "e0f78acfc9fef52b2fc11a2942290403ceca3b505a8e515defda8fbf68ac3b13"


	condition:
		androguard.package_name("com.fingersoft.hillclimb") and
		not androguard.certificate.sha1("9AA52CC5C1EA649B45F295611417B4B6DA6324EA")
}