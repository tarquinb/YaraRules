import "androguard"

rule Leecher_A
{
    condition:
        androguard.certificate.sha1("B24C060D41260C0C563FEAC28E6CA1874A14B192")
}