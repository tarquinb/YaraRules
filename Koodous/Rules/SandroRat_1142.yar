rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"

	strings:
		$a = "SandroRat_Configuration_Database"
		$b = "SandroRat_BrowserHistory_Database"
		$c = "SandroRat_Configuration_Database"
		$d = "SandroRat_CallRecords_Database"
		$e = "SandroRat_RecordedSMS_Database"
		$f = "SandroRat_CurrentSMS_Database"
		$g = "SandroRat_Contacts_Database"

	condition:
		any of them
		
}