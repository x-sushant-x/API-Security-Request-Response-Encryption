package main

import (
	"fmt"
)

func main() {
	publicKey := `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvFH5SbRo8EMN7q31/Rxd5kfsxUeTs5EN/C6pYi4fyE7TXxMZVfUZ
Zy2PuMeb+xifjfY9CiGf8ZtEHFfDWG3ZXQlS6y7eeib0QAkhtgKwI+Bvzpiz/xta
ql41I50mMRMbU97NsVazq4TmiNz9bSdTfBC3QT7posl0Iq1aelTWf8q/q6t5yESu
BDEojwvsp6iaxXMr87sKeh3WZMvPuPYGQa8ZZ6PdLLBCeGbYpXc2TmvPR1bn+tId
Swcf+I7ET4J1zMOpwqVkQlXdoLa3/kUufMT+VOfmAlQcpXgByppKHshBh6LAPUZ3
6avB6TT2PWtxVYdaaVUkM/HRes4EGc91ZQIDAQAB
-----END RSA PUBLIC KEY-----`

	encryptedData := EncryptWithRSA("Hi, Sushant Here!", publicKey)
	fmt.Println("Encrypted Data: " + encryptedData)

	decryptedData := DecryptWithRSA(encryptedData)
	fmt.Println("Decrypted Data: " + decryptedData)
}

func CheckPanic(err error) {
	if err != nil {
		panic(err)
	}
}
