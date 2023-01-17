package mtk

import "testing"

func TestEncrypt(t *testing.T) {
	d := NewDPAPI()
	encrypted, err := d.Encrypt([]byte("test"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := d.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "test" {
		t.Fatal("decrypted data does not match")
	}
}

func TestEncryptLM(t *testing.T) {
	d := NewDPAPI()
	encrypted, err := d.Encrypt([]byte("test"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := d.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "test" {
		t.Fatal("decrypted data does not match")
	}
}

func TestEncryptEntropy(t *testing.T) {
	d := NewDPAPI()
	encrypted, err := d.Encrypt([]byte("test"), []byte("myEntropy"), true)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := d.Decrypt(encrypted, []byte("myEntropy"))
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "test" {
		t.Fatal("decrypted data does not match")
	}
}

func TestDecryptFail(t *testing.T) {
	d := NewDPAPI()
	if _, err := d.Decrypt("test", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptFailEntropy(t *testing.T) {
	d := NewDPAPI()
	encrypted, err := d.Encrypt([]byte("test"), []byte("myEntropy"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decrypt(encrypted, []byte("wrongEntropy")); err == nil {
		t.Fatal("expected error")
	}
}

func TestFailBlob(t *testing.T) {
	blob := newBlob(nil)
	if blob.pbData != nil {
		t.Fatal("expected nil")
	}
}
