package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"time"
)

const (
	encryptedFile = "EncryptedFile.enc"
	text          = "testfile.txt"
)

func main() {
	// 32 bit lenght key
	key := ("KeyNeedsToBe32BytesAndWeAreThere")
	// Random text we are encrypting and decrypting
	plaintext, _ := ioutil.ReadFile(fmt.Sprintf(text))
	// iv length should be the same length as the blocksize
	// Encrypting the plain text with the given key and iv.
	EncryptToFile(key, string(plaintext), encryptedFile)
	// Decrypting the file whe made with encrypt, with the given key and iv
	decryptText := DecryptFromFile(key, encryptedFile)
	// printing out the decrypted text
	fmt.Printf("Decrypted Message: %s", decryptText)

	fmt.Println()
	fmt.Println("test res enc/dec")
	n, e, d := KeyGen(2050)
	m1 := new(big.Int)
	m1 = big.NewInt(12345)
	fmt.Println(m1)
	c := encrypt(m1, e, n)
	fmt.Println(c)
	m2 := decrypt(c, d, n)
	fmt.Println(m2)

	fmt.Println("test res sign :")
	p, _ := rand.Prime(rand.Reader, 2000)
	message := p
	start := time.Now()
	signature := sign(d, n, message)
	t := time.Now()
	elapsed := t.Sub(start)
	fmt.Println(signature)
	fmt.Printf("Computing this took %s\n", elapsed)
	fmt.Println(verify(e, n, message, signature))
	message.Sub(message, big.NewInt(1))
	fmt.Println(verify(e, n, message, signature))
	message.Add(message, big.NewInt(1))
	fmt.Println(verify(e, n, message, signature))
	fmt.Println(n.BitLen())
	fmt.Println(signature.BitLen())

	h := sha256.New()
	//h(m)
	start2 := time.Now()
	h.Write(plaintext)
	t2 := time.Now()
	elapsed2 := t2.Sub(start2)
	elapsedInSeconds := elapsed2.Seconds()
	bitsPerSecond := 80000 / elapsedInSeconds
	fmt.Printf("We can hash at %s bits per second\n", bitsPerSecond)

	TestGenerateSign()
}

// Encrypting a plaintext, with the given key and iv.
// After encrypting the text it writes the encryption to Encryptedfile.enc
// which is a new file who just got created. After writing to the file,
// the function prints out a print statement.
func EncryptToFile(key string, plaintext string, fileName string) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
	}
	cipherText := make([]byte, aes.BlockSize+len(plaintext))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	fmt.Println("iv,block")
	fmt.Println(len(iv))
	fmt.Println(block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plaintext))

	err = ioutil.WriteFile(fmt.Sprintf(fileName), cipherText, 0644)
	if err != nil {
		log.Fatalf("Writing encryption file: %s", err)
	} else {
		fmt.Printf("Message encrypted in file: %s\n\n", fileName)
	}
}

// Decrypting the file created by encrypt, with the given key and iv.
// After loading the encrypted file, the function decrypts the file,
// and returns the deciphered text

func DecryptFromFile(key string, fileName string) []byte {
	cipherText, _ := ioutil.ReadFile(fmt.Sprintf(fileName))
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(cipherText, cipherText)

	return cipherText
}

func KeyGen(keyLength int) (n *big.Int, e *big.Int, d *big.Int) {
	for {
		n = new(big.Int)
		e = big.NewInt(3)
		d = new(big.Int)
		if keyLength <= 3 {
			fmt.Println("Error: key length needs to be at least 4")
			return
		}

		p, err := rand.Prime(rand.Reader, keyLength/2)
		if err != nil {
			fmt.Println("error creating primes:")
			fmt.Println(err)
		}
		q, err := rand.Prime(rand.Reader, keyLength/2)
		if err != nil {
			fmt.Println("error creating primes:")
			fmt.Println(err)
		}

		//calculate n
		n.Set(p)
		n.Mul(n, q)
		if n.BitLen() != keyLength {
			continue
		}

		//calculate d
		q.Sub(q, big.NewInt(1))
		p.Sub(p, big.NewInt(1))

		product := new(big.Int)
		product = product.Mul(q, p)
		//d.Mod(temp, product)

		d = d.ModInverse(e, product)

		if d == nil {
			continue
		}
		//return
		return n, e, d
	}

}

func encrypt(m *big.Int, e *big.Int, n *big.Int) *big.Int {
	c := new(big.Int)
	//m^e mod n
	c = c.Exp(m, e, n)
	return c
}

func decrypt(c *big.Int, d *big.Int, n *big.Int) *big.Int {
	m := new(big.Int)
	//c^d mod n
	m = m.Exp(c, d, n)
	return m
}

func sign(d *big.Int, n *big.Int, m *big.Int) *big.Int {
	h := sha256.New()
	//h(m)
	h.Write(m.Bytes())
	//for i:=0;i<1000000;i++{h.Write(h.Sum(nil))}
	b := new(big.Int)
	b.SetBytes(h.Sum(nil))
	//h(m)^d mod n
	signature := b.Exp(b, d, n)
	return signature
}

func verify(e *big.Int, n *big.Int, m *big.Int, s *big.Int) bool {
	b := new(big.Int)
	res := new(big.Int)
	//s^e mod n
	res.Exp(s, e, n)

	h := sha256.New()
	//h(m)
	h.Write(m.Bytes())
	//for i:=0;i<1000000;i++{h.Write(h.Sum(nil))}
	b.SetBytes(h.Sum(nil))
	fmt.Println("res and s:")
	fmt.Println(res)
	fmt.Println(b)
	if b.Cmp(res) == 0 {
		return true
	}
	return false
}

// Generates a secret and public key, returns the public key and saves the secret key
// in a encrypted file.
func Generate(filename string, password string) string {
	password = passwordConcat(password)
	n, e, d := KeyGen(2050)
	publicKey := n.String() + ";" + d.String()
	secretKey := n.String() + ";" + e.String()
	EncryptToFile(password, secretKey, filename)
	return publicKey
}

// Decrypts the message and signs it, returns the signature.
func Sign(filename string, password string, msg []byte) string {
	password = passwordConcat(password)
	secretKey := string(DecryptFromFile(password, filename))
	ndString := strings.Split(secretKey, ";")
	n, _ := new(big.Int).SetString(ndString[0], 10)
	d, _ := new(big.Int).SetString(ndString[1], 10)
	msgBI := new(big.Int).SetBytes(msg)
	signature := sign(d, n, msgBI).String()
	return signature
}

func passwordConcat(password string) string {
	if len(password) < 32 {
		for len(password) < 32 {
			password = password + "a"
		}
	}
	return password
}

func TestGenerateSign() {
	filename := "TestGenerateSign"
	password := "KeyVerySafe"
	message := []byte("Denne besked skal signes af Sign metoden.")
	publicKey := Generate(filename, password)
	signature := Sign(filename, password, message)
	neString := strings.Split(publicKey, ";")
	n, _ := new(big.Int).SetString(neString[0], 10)
	e, _ := new(big.Int).SetString(neString[1], 10)
	signatureBI, _ := new(big.Int).SetString(signature, 10)
	decryptsignature := decrypt(signatureBI, e, n).String()
	messageBI := new(big.Int).SetBytes(message)
	h := sha256.Sum256(messageBI.Bytes())
	x := h[:]
	testhash := big.NewInt(0).SetBytes(x).String()
	fmt.Println("TestGenerateSign kommer her")
	fmt.Println("DecryptedSignature:" + decryptsignature)
	fmt.Println("Test hash:         " + testhash)
	if decryptsignature == testhash {
		fmt.Println("hashstringene er ens")
	}
}
