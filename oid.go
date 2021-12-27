package pkcs7

import (
	"encoding/asn1"
)

var (

	oidData                               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	oidTc26Gost34102012256                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	oidTc26Gost34102012512                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	oidTc26Gost34112012256                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidTc26Gost34112012512                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
	oidTc26signwithdigestgost341012256    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidTc26signwithdigestgost341012512    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidTc26agreementgost341012256         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 1}
	oidTc26agreementgost341012512         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 2}
	oidTc26Gost34102012256Signature       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidTc26Gost34102012512Signature       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidGostR34102001CryptoProAParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
	oidGostR34102001CryptoProBParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
	oidGostR34102001CryptoProCParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}
	oidGostR34102001CryptoProXchAParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	oidGostR34102001CryptoProXchBParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}
	oidTc26Gost34102012256ParamSetA       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	oidTc26Gost34102012256ParamSetB       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
	oidTc26Gost34102012256ParamSetC       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
	oidTc26Gost34102012256ParamSetD       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}
	oidTc26Gost34102012512ParamSetA       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	oidTc26Gost34102012512ParamSetB       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	oidTc26Gost34102012512ParamSetC       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
	oidtc26gost341112256                  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidtc26gost341112512                  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

	//GOST signature algorithms  
	oidSignatureGOSTR3410_2001              = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	oidSignatureGOSTR3410_2001_GOSTR3411_94 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 3}

	//GOST hash function oid
	oidGOST_R341194 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
)

