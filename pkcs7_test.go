package pkcs7

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestSign(t *testing.T) {
	var signature = []byte(`12345678901234567890`)
	var certPem      = []byte(`
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIIfE8EORzUmS0wDQYJKoZIhvcNAQEFBQAwRDELMAkGA1UE
BhMCVVMxFDASBgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVz
dCBOZXR3b3JraW5nMB4XDTEwMDEyOTE0MDgyNFoXDTMwMTIzMTE0MDgyNFowRDEL
MAkGA1UEBhMCVVMxFDASBgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZp
cm1UcnVzdCBOZXR3b3JraW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAtITMMxcua5Rsa2FSoOujz3mUTOWUgJnLVWREZY9nZOIG41w3SfYvm4SEHi3y
YJ0wTsyEheIszx6e/jarM3c1RNg1lho9Nuh6DtjVR6FqaYvZ/Ls6rnla1fTWcbua
kCNrmreIdIcMHl+5ni36q1Mr3Lt2PpNMCAiMHqIjHNRqrSK6mQEubWXLviRmVSRL
QESxG9fhwoXA3hA/Pe24/PHxI1Pcv2WXb9n5QHGNfb2V1M6+oF4nI979ptAmDgAp
6zxG8D1gvz9Q0twmQVGeFDdCBKNwV6gbh+0t+nvujArjqWaJGctB+d1ENmHP4ndG
yH329JKBNv3bNPFyfvMMFr20FQIDAQABo0IwQDAdBgNVHQ4EFgQUBx/S55zawm6i
QLSwelAQUHTEyL0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJ
KoZIhvcNAQEFBQADggEBAIlXshZ6qML91tmbmzTCnLQyFE2npN/svqe++EPbkTfO
tDIuUFUaNU52Q3Eg75N3ThVwLofDwR1t3Mu1J9QsVtFSUzpE0nPIxBsFZVpikpzu
QY0x2+c06lkh1QF612S4ZDnNye2v7UsDSKegmQGA3GWjNq5lWUhPgkvIZfFXHeVZ
Lgo/bNjR9eUJtGxUAArgFU2HdW23WJZa3W3SAKD0m0i+wzekujbgfIeFlxoVot4u
olu9rxj5kFDNcFn4J2dHy8egBzp90SxdbBk6ZrV9/ZFvgrG+CJPbFEfxojfHRZ48
x3evZKiT3/Zpg4Jg8klCNO1aAFSFHBY2kgxc+qatv9s=
-----END CERTIFICATE-----`)
	var outSign = string(`MIIEFAYJKoZIhvcNAQcCoIIEBTCCBAECAQExDjAMBggqhQMHAQECAgUAMAsGCSqGSIb3DQEHAaCCA1AwggNMMIICNKADAgECAgh8TwQ5HNSZLTANBgkqhkiG9w0BAQUFADBEMQswCQYDVQQGEwJVUzEUMBIGA1UECgwLQWZmaXJtVHJ1c3QxHzAdBgNVBAMMFkFmZmlybVRydXN0IE5ldHdvcmtpbmcwHhcNMTAwMTI5MTQwODI0WhcNMzAxMjMxMTQwODI0WjBEMQswCQYDVQQGEwJVUzEUMBIGA1UECgwLQWZmaXJtVHJ1c3QxHzAdBgNVBAMMFkFmZmlybVRydXN0IE5ldHdvcmtpbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0hMwzFy5rlGxrYVKg66PPeZRM5ZSAmctVZERlj2dk4gbjXDdJ9i-bhIQeLfJgnTBOzISF4izPHp7-NqszdzVE2DWWGj026HoO2NVHoWppi9n8uzqueVrV9NZxu5qQI2uat4h0hwweX7meLfqrUyvcu3Y-k0wICIweoiMc1GqtIrqZAS5tZcu-JGZVJEtARLEb1-HChcDeED897bj88fEjU9y_ZZdv2flAcY19vZXUzr6gXicj3v2m0CYOACnrPEbwPWC_P1DS3CZBUZ4UN0IEo3BXqBuH7S36e-6MCuOpZokZy0H53UQ2Yc_id0bIffb0koE2_ds08XJ-8wwWvbQVAgMBAAGjQjBAMB0GA1UdDgQWBBQHH9LnnNrCbqJAtLB6UBBQdMTIvTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAiVeyFnqowv3W2ZubNMKctDIUTaek3-y-p774Q9uRN860Mi5QVRo1TnZDcSDvk3dOFXAuh8PBHW3cy7Un1CxW0VJTOkTSc8jEGwVlWmKSnO5BjTHb5zTqWSHVAXrXZLhkOc3J7a_tSwNIp6CZAYDcZaM2rmVZSE-CS8hl8Vcd5VkuCj9s2NH15Qm0bFQACuAVTYd1bbdYllrdbdIAoPSbSL7DN6S6NuB8h4WXGhWi3i6iW72vGPmQUM1wWfgnZ0fLx6AHOn3RLF1sGTpmtX39kW-Csb4Ik9sUR_GiN8dFnjzHd69kqJPf9mmDgmDySUI07VoAVIUcFjaSDFz6pq2_2zGBijCBhwIBATBQMEQxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtBZmZpcm1UcnVzdDEfMB0GA1UEAwwWQWZmaXJtVHJ1c3QgTmV0d29ya2luZwIIfE8EORzUmS0wDAYIKoUDBwEBAgIFADAMBggqhQMHAQEBAQUABBQxMjM0NTY3ODkwMTIzNDU2Nzg5MA`)
    blockCkey, _ := pem.Decode(certPem)
    if blockCkey == nil || blockCkey.Type != "CERTIFICATE" {
	t.Errorf("failed to decode PEM block containing private key ")
    }

    cert, err		:= x509.ParseCertificate(blockCkey.Bytes)
    if err != nil {
	t.Errorf("failed ParseCertificate %v", err)
    }
    var priv = []byte(`
-----BEGIN PRIVATE KEY-----
MEMCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIOOb5GabRYCfBJmH
Egl7OfqChYELQexC7SFV8QLTiX4q
-----END PRIVATE KEY-----
`)
    blockPkey, _ := pem.Decode(priv)
    if blockPkey == nil || blockPkey.Type != "PRIVATE KEY" {
	t.Errorf("failed to decode PEM block containing private key ")
    }

    key, err := ParsePKCS8PrivateKey(blockPkey.Bytes)
    if err != nil {
	t.Errorf("ParsePKCS8PrivateKey() error = %v, key %v", err, key)
	return
    }

    signedData, err := NewSignedData()
    if err != nil {
	t.Errorf("failed cannot initialize signed data: %v", err)
    }

    if err := signedData.AddSigner(cert, key, signature); err != nil {
	t.Errorf("failed cannot add signer: %v", err)
    }

    data, err := signedData.Finish()
    if err != nil {
	t.Errorf("failed cannot signing data: %v", err)
    }
    if base64.RawURLEncoding.EncodeToString(data) != outSign{
	t.Errorf("failed cannot signing data: %v", base64.RawURLEncoding.EncodeToString(data))
    }

}
