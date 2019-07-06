
import "androguard"


rule whatsapp:fake

{

    condition:

        androguard.app_name("WhatsApp") and

        not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")

}


rule king_games:fake

{

    condition:

        (androguard.app_name("AlphaBetty Saga")

        or androguard.app_name("Candy Crush Soda Saga")

        or androguard.app_name("Candy Crush Saga")

        or androguard.app_name("Farm Heroes Saga")

        or androguard.app_name("Pet Rescue Saga")

        or androguard.app_name("Bubble Witch 2 Saga")

        or androguard.app_name("Scrubby Dubby Saga")

        or androguard.app_name("Diamond Digger Saga")

        or androguard.app_name("Papa Pear Saga")

        or androguard.app_name("Pyramid Solitaire Saga")

        or androguard.app_name("Bubble Witch Saga")

        or androguard.app_name("King Challenge"))

        and not androguard.certificate.sha1("9E93B3336C767C3ABA6FCC4DEADA9F179EE4A05B")

        and not androguard.certificate.sha1("F22BD3F8C24AB1451ABFD675788B953C325AB550")

}


/*

rule facebook:fake

{

    condition:

        androguard.app_name("Facebook")

        and not androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9")

        and not androguard.certificate.sha1("330DF1D4F77968C397FF53D444089BB46DC330F1") //OEM Sony Ericcson Facebook app

}*/


rule instagram:fake

{

    condition:

        androguard.app_name("Instagram")

        and not androguard.certificate.sha1("C56FB7D591BA6704DF047FD98F535372FEA00211")

}