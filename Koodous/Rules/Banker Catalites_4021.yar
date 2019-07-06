rule detection
{
    strings:
	  $ = "Added %1$s to %2$s balance"  nocase
	  $ = "money_was_add"  nocase
	  //$ = "Android System Update"  nocase
	  $ = "!!Touch to sign in to your account"  nocase
	  $ = "You will be automatically charged %1$s"  nocase
	  $ = "adm_win"  nocase
	  $ = "shhtdi"  nocase
	  $ = "chat_interface"  nocase
	  $ = "chat_receive"  nocase
	  $ = "chat_sent"  nocase
	  $ = "chat_row" nocase

	
	condition:
		all of them

}