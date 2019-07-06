// First, we put an identifying name to the rule  
 rule androrat  
 {  
     meta:  
         description = “This malware is a bot that allows sms hook, calls and other information”  
         source = “Source from which we extracted the information, if not own”  
         author = “asanchez@koodous.com”  
     strings:  
         //Then we will define the string that we will use in the rule  
         $activity = “AndroratActivity.java”  
         $classPath = “my/app/client/AndroratActivity”  
         $method = “Androrat.Client.storage”  
     condition:  
         //The condition for the rule generates a positive, in this case we want all strings are because we know they are sufficiently identifying  
         all of them  
         // But we can also say that some of them be  
         // any of them  
         // 2 of them   
 }