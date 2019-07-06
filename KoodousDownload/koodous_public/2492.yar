import "androguard"

rule experimental
{
 
	strings:
		$ = "Th.Dlg.Fll13" nocase
		$ = "alluorine.info" nocase
		$ = "mancortz.info" nocase
		$ = "api-profit.com" nocase
		$ = "narusnex.info" nocase
		$ = "ronesio.xyz" nocase
		$ = "alluorine.info" nocase
		$ = "meonystic.info" nocase
		$ = "api-profit.com" nocase
		$ = "narusnex.info" nocase
		$ = "ngkciwmnq.info" nocase
		$ = "golangwq.info" nocase
		$ = "krnwhyvq.info" nocase
		$ = "nvewpvnid.info" nocase
		$ = "ovnwislxf.info" nocase
		$ = "deputizem.info" nocase
		
	condition:
		1 of them

}