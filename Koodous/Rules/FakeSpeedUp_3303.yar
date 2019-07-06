import "androguard"


rule rest
{
	strings:
		$ = "cards, you can resolve the confusion within your heart. Every card has two" 
	  	$ = "sides, representing the Pros and Cons of a subject. All the answers are" 
		$ = "First of all, this is a free software, but due to the high development costs" 

	condition:
		all of them
		
}