import "androguard"

rule FakeUpdate
{
    condition:
        androguard.certificate.sha1("45167886A1C3A12212F7205B22A5A6AF0C252239")
        
        
}