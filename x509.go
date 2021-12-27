package pkcs7

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"go.cypherpunks.ru/gogost/v5/gost3410"
)

type KeyAlgorithm int

const (
	UnknownKeyAlgorithm KeyAlgorithm = iota
	GOST
)

type GostR3410KeyParameters struct {
	KeyParamSet       asn1.ObjectIdentifier
	DigestParamSet    asn1.ObjectIdentifier `asn1:"optional"`
}

func getKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) KeyAlgorithm {
	switch {
	    case oid.Equal(oidSignatureGOSTR3410_2001):
		return GOST
	    case oid.Equal(oidTc26Gost34102012256):
		return GOST
	    case oid.Equal(oidTc26Gost34102012512):
		return GOST
	    case oid.Equal(oidTc26agreementgost341012256):
		return GOST
	    case oid.Equal(oidTc26agreementgost341012512):
		return GOST
	    case oid.Equal(oidTc26signwithdigestgost341012256):
		return GOST
	    case oid.Equal(oidTc26signwithdigestgost341012512):
		return GOST
	}
	return UnknownKeyAlgorithm
}

func getCurve(algo pkix.AlgorithmIdentifier) (curve *gost3410.Curve, err error) {

	var keyParams GostR3410KeyParameters

	params := algo.Parameters.FullBytes

	restBytes, err := asn1.Unmarshal(params, &keyParams)

	if err != nil {
		return nil, errors.New("x509: failed to parse GOST parameters")
	}

	if len(restBytes) != 0 {
		return nil, errors.New("x509: there is data after GOST parameters ")
	}

	switch {
	    case keyParams.KeyParamSet.Equal(oidGostR34102001CryptoProAParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
	    case keyParams.KeyParamSet.Equal(oidGostR34102001CryptoProBParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
	    case keyParams.KeyParamSet.Equal(oidGostR34102001CryptoProCParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
	    case keyParams.KeyParamSet.Equal(oidGostR34102001CryptoProXchAParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
	    case keyParams.KeyParamSet.Equal(oidGostR34102001CryptoProXchBParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
	    case keyParams.KeyParamSet.Equal(oidTc26Gost34102012256ParamSetA):
		curve = gost3410.CurveIdtc26gost34102012256paramSetA()
	    case keyParams.KeyParamSet.Equal(oidTc26Gost34102012256ParamSetB):
		curve = gost3410.CurveIdtc26gost34102012256paramSetB()
	    case keyParams.KeyParamSet.Equal(oidTc26Gost34102012256ParamSetC):
		curve = gost3410.CurveIdtc26gost34102012256paramSetC()
	    case keyParams.KeyParamSet.Equal(oidTc26Gost34102012256ParamSetD):
		curve = gost3410.CurveIdtc26gost34102012256paramSetD()
	    default:
		return nil, errors.New("x509: unknown GOST curve")
	}
	return curve, nil
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// options
}

func ParsePKCS8PrivateKey(derBytes []byte) (key *gost3410.PrivateKey, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(derBytes, &privKey); err != nil {
		return nil, err
	}
	algo := getKeyAlgorithmFromOID(privKey.Algo.Algorithm)
	switch algo {
	case GOST:
		privRaw := make([]byte,32)
		copy(privRaw, privKey.PrivateKey[:32])
		curve, err := getCurve(privKey.Algo)
		if err != nil {
			return nil, err
		}
		return gost3410.NewPrivateKey(curve, privKey.PrivateKey)
	default:
		return nil, fmt.Errorf("x509: PKCS#8 unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}
