import "androguard"


rule PimentoRoot : rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
		
}