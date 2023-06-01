package mtk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// NewKeyPair creates a new RSA key pair of the given bit size
// BitSizes 2048=RSA2048, 3072=RSA3072, 4096=RSA4096
// Password is optional - if empty, no password will be used
func NewKeyPair(bits int, password string) (keyPair *KeyPair, err error) {
	kp := &KeyPair{}
	if err = kp.generate(bits, password); err != nil {
		return nil, err
	}
	return kp, nil
}

// Generate private and public key pair
func (kp *KeyPair) generate(bits int, password string) (err error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	if kp.PrivateKey, err = kp.privateKeyToBytes(privkey, password); err != nil {
		return err
	}
	if kp.PublicKey, err = kp.publicKeyToBytes(&privkey.PublicKey); err != nil {
		return err
	}
	return nil
}

func (kp *KeyPair) privateKeyToBytes(priv *rsa.PrivateKey, password string) (privateKey []byte, err error) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	if password != "" {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}
	return pem.EncodeToMemory(block), nil
}

func (kp *KeyPair) publicKeyToBytes(pub *rsa.PublicKey) (publicKey []byte, err error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes, nil
}
