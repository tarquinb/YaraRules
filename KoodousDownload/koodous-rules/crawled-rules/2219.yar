
rule android_metasploit : android

{

    meta:

      author = "https://twitter.com/plutec_net"

      description = "This rule detects apps made with metasploit framework"


    strings:

      $a = "*Lcom/metasploit/stage/PayloadTrustManager;"

      $b = "(com.metasploit.stage.PayloadTrustManager"

      $c = "Lcom/metasploit/stage/Payload$1;"

      $d = "Lcom/metasploit/stage/Payload;"


    condition:

      $a or $b or $c or $d

}