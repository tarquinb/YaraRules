import "androguard"

rule test: adware
{
		
    condition:
		androguard.app_name(/{d0 a3 d1 81 d1 82 d0 b0 d0 bd d0 be d0 b2 d0 ba d0 b0}/) or androguard.package_name(/com\.tujtr\.rtbrr/)
}