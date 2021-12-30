package pkcs7

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"github.com/Theo730/gogost/gost3410"
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type SignedData struct {
	data          data
	certificates  []*x509.Certificate
}

type data struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CertificatesList           []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

func NewSignedData() (*SignedData, error) {
	contentInfo := contentInfo{
		ContentType: oidData,
	}
	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidTc26Gost34112012256,
		Parameters: asn1.RawValue{Class: 0, Tag: 5 },
	}
	data := data{
		ContentInfo:                contentInfo,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
	}
	
	return &SignedData{data: data }, nil
}

func (sd *SignedData) AddSigner(cert *x509.Certificate, pkey *gost3410.PrivateKey, signature []byte) error {

	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		return err
	}

	signer := signerInfo{
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidTc26Gost34102012256, Parameters: asn1.RawValue{Class: 0, Tag: 5 },},
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidTc26Gost34112012256, Parameters: asn1.RawValue{Class: 0, Tag: 5 },},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}

	sd.certificates = append(sd.certificates, cert)
	sd.data.SignerInfos = append(sd.data.SignerInfos, signer)
	return nil
}

func (sd *SignedData) Finish() ([]byte, error) {
	sd.data.Certificates = marshalCertificates(sd.certificates)
	inner, err := asn1.Marshal(sd.data)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

func cert2issuerAndSerial(cert *x509.Certificate) (ias issuerAndSerial, err error) {

	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

func marshalCertificates(certs []*x509.Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}
