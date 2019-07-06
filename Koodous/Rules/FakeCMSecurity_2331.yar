import "androguard"

rule FakeCMSecurity: Certs
{
    condition:
        androguard.certificate.sha1("2E66ED3E9EE51D09A8EFCE00D32AE5E078F1F1B6")
        
}