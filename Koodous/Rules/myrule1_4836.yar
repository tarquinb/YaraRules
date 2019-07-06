import "androguard"

private global rule whatever2
{
	condition:
		androguard.app_name(/a/) or
		androguard.app_name(/b/) or
		androguard.app_name(/c/) or
		androguard.app_name("Materialize Your App")
}