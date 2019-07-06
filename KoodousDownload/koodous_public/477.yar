import "androguard"
import "cuckoo"

rule shiny_adware
{
	condition:
		androguard.package_name(/com.shiny*/) and cuckoo.network.http_request(/http:\/\/fingertise\.com/)
}