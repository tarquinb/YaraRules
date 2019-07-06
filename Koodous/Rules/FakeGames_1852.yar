import "androguard"
import "file"
import "cuckoo"


rule Fake_SuperCell {
    meta:
        description = "This rule aims to detect fake games from SuperCell. Current list of games included: Clash of Clans, Clash Royale, Hay Day"
    condition:
		(androguard.app_name(/clash royale/i) 
		and not 
		androguard.certificate.sha1("2E18D3F8726B1DE631322716518FB2AEC2EBEB9E")) 
		or (androguard.certificate.sha1("456120D30CDA8720255B60D0324C7D154307F525") 
		and not androguard.app_name(/clash of clans/i)) 
		or (androguard.certificate.sha1("1E7C404B0EE0749CF936606C3EC34CF9D3283BE3") 
		and not androguard.app_name(/hay day/i)) 
		or (androguard.app_name(/boom beach/i) 
		and not androguard.certificate.sha1("C568F735B129423014938283809A36DEA8EBD3A4"))
		
}