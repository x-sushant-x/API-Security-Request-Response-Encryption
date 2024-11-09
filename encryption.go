package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func EncryptWithRSA(message string, publicKeyString string) string {
	publicKey, err := ParsePublicKeyFromString(publicKeyString)
	CheckPanic(err)

	chiperText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(message))
	CheckPanic(err)

	chiperTextString := base64.StdEncoding.EncodeToString(chiperText)
	return chiperTextString
}

func DecryptWithRSA(encryptedData string) string {
	privateKeyString := `-----BEGIN RSA PRIVATE KEY-----
	MIIEpAIBAAKCAQEAvFH5SbRo8EMN7q31/Rxd5kfsxUeTs5EN/C6pYi4fyE7TXxMZ
	VfUZZy2PuMeb+xifjfY9CiGf8ZtEHFfDWG3ZXQlS6y7eeib0QAkhtgKwI+Bvzpiz
	/xtaql41I50mMRMbU97NsVazq4TmiNz9bSdTfBC3QT7posl0Iq1aelTWf8q/q6t5
	yESuBDEojwvsp6iaxXMr87sKeh3WZMvPuPYGQa8ZZ6PdLLBCeGbYpXc2TmvPR1bn
	+tIdSwcf+I7ET4J1zMOpwqVkQlXdoLa3/kUufMT+VOfmAlQcpXgByppKHshBh6LA
	PUZ36avB6TT2PWtxVYdaaVUkM/HRes4EGc91ZQIDAQABAoIBAQCSfOWAetDCTDaz
	OijGOeGk9r/r+bCgFq6dQyLJV32rj/2F0FJ99clL5DoPD157JP1ALZHvppZHF3MU
	5QP0boaNg2o3vV6cAF8wzKmnblHbpoLyXwBs6bdOHTgSuvRxah5w0DiKwRnDyv6U
	6epMlTGwqUQTgb+1vCUVsGlYDVRJVHTJ0XTuC2BDRvLChB9fa3etOpiWLwyBD8J3
	E9shBcoWGB4RN2ccPinb1Q4n9TSxwkUv5rs4h8lTkAZQ2A8nLdvgwPvie1LzYUl8
	VtjXyJMeDyliy+YUIQ+tz/Z5vZPXf6662uOGpQNP9QUGaBaMJh0gSBvlnFSu52cT
	XmzFtaAhAoGBANrojhmKU8TAK8dVokRtmR/vT3WREdD4xZ7HYQL+LaCVaw4UkTJP
	fDiSKd2aF/v0H9200G//lDcoddrizafvFsQQlB15lb+j4QfnWLQfYwPEnE1U19NQ
	Oh66sXg2s8QbYkvAdp1xBEAgP3ZbSMHwE7xOxClBQbEfCQ+uyekbnajpAoGBANw6
	nUTtMi0mhIIiTbZKL5U6Fu2daVSU4fL5dTaxTqvTiMZs6X+Dg8hJQtS5VL/b8kq8
	gwxdl12owUHydIFUylj5Uf+dqk2vadP5MOofEDsv8dE8DikP5pS2r/+p9yhJ0In5
	mhvUhEDPl87b6KJV/JKH0X90tzR0hsjDXb8lVNsdAoGAUDctcwB0R8GfiTDBAFAk
	70XTGSKqo6e1SsSGsQERGSoHi6ZPul7UByrQOorvxPyk/Kn4Q0IlPr0NysKXV7VN
	41Sr4c0e6ZWUrT/CCmcB8myGVfQEDkP0uDPzOjjZUMA0GcwR6wlx5Ems16MFm0Nt
	B/DZAsEN4Gid+mgzRr8+25kCgYBUA0RFrBrtIHmCT2XH+asHSX6/rMIm0xkTINj3
	QVKat/rAf4Hf9CLMwC3virfq7RQUMK/pgragsyTubHjHcbozkQEX+2SheB5uD+z6
	E1mUyqh8QmXAgmFbMAoaBRPVWbtlN0P0A/Fj7A2kiz3G1/ifSZLBBZxyNVXJtsXH
	io1BfQKBgQDHgeMSyWd6ujXoF1Xp3tlDe49K/is9DYILFA9hORPWL/B7lzJPHxPg
	GX33GREJx8eZtfZeFJCWx7Ez+40eUKT2AMidPAiWeHHTljI5QHHZ6zoLjfbOENER
	2rxJ59yFA14dz7sHDg7rAJOTEi6qA/b8XFNeSADEUXOHWPv5j7qjMA==
	-----END RSA PRIVATE KEY-----`

	privateKey, err := ParsePrivateKeyFromString(privateKeyString)
	CheckPanic(err)

	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	CheckPanic(err)

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedBytes)
	CheckPanic(err)

	return string(decryptedData)
}
