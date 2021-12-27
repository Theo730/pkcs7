package pkcs7

import (
	"encoding/pem"
	"testing"
)

func TestParsePKCS8PrivateKey(t *testing.T) {
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
    if key.Key.String() != "19220713598767424848842454796960079228663739716629146398466089230109098941411"{
	t.Errorf("ParsePKCS8PrivateKey() error BigInt does not match, BigInt = %s(19220713598767424848842454796960079228663739716629146398466089230109098941411)", key.Key.String())
	return

    } 


}
