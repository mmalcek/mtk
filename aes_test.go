package mtk

import "testing"

func TestAESencrypt(t *testing.T) {
	encrypted, err := AESencrypt([]byte("test"), "test")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := AESdecrypt(encrypted, "test")
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "test" {
		t.Fatal("decrypted data does not match")
	}
}

func TestAESdecryptFail2(t *testing.T) {
	if _, err := AESdecrypt("test", "hello"); err == nil {
		t.Fatal("expected error")
	}
}

func TestAESencryptFailPassphrase(t *testing.T) {
	encrypted, err := AESencrypt([]byte("test"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AESdecrypt(encrypted, "hello"); err == nil {
		t.Fatal("expected error")
	}
}
