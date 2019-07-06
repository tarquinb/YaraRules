import "androguard"


rule AiQingYingShi : chinese_porn
{

	condition:
	androguard.app_name(/\xe7\x88\xb1\xe6\x83\x85[\w]+?\xe5\xbd\xb1\xe8\xa7\x86[\w]{,11}/)  //273bcec861e915f39572a169ae98d4c2afae00800259c1fe5e28c075923d90ca
		
}