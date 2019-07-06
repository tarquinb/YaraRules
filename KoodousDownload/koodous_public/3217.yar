import "androguard"


rule pokemon
{
	condition:

		androguard.app_name(/pokemongo/i)
		
}