package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"strings"
)

var (
	secretKey *string //= "abcdabcdabcdabcdabcdabcdabcdabcd"
	generator int64
	prime     int64
	port      *int
	address   *string
	SK        *int
)

type Node struct {
	PK_A, PK_B int64
}

func main() {

	port = flag.Int("p", -1, "Port")
	address = flag.String("a", "", "Address")
	SK = flag.Int("sk", 0, "Key")
	secretKey = flag.String("e", "", "end key")

	*address = strings.TrimSpace(*address)

	flag.Parse()

	running := true
	res := bufio.NewReader(os.Stdin)
	var s string
	m := make(map[string]func([]string))

	m["SR"] = SR
	m["enc"] = enc

	n := &Node{}

	n.server()

	for running {

		fmt.Print("::> ")
		s, _ = res.ReadString('\n')

		s = strings.TrimSpace(s)
		args := strings.Split(s, " ")

		f, ok := m[args[0]]
		if ok {
			f(args)
		}

	}

	f, err := os.Open("hello.txt")
	if err != nil {
		fmt.Println(err)
	}

	content, err := io.ReadAll(f)
	if err != nil {
		fmt.Println(err)
	}

	f.Close()
	//plainText := "My message My message My message My message My message My message My message My message My message My message My message My message My message My message My message"
	key := "abcdabcdabcdabcdabcdabcdabcdabcd"

	emsg, err := EncryptMessage([]byte(key), string(content))
	if err != nil {
		fmt.Println(err)
	}

	dmsg, err := DecryptMessage([]byte(key), emsg)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Encrypted: ", emsg)

	fmt.Println("Encrypted: ", dmsg)

	//fmt.Println("Dencrypted: ", dmsg)

}

func SR(args []string) {

	PK := int64(math.Mod(math.Pow(13, float64(*SK)), 479))
	fmt.Println("PK: ", PK)

	err := SendRequest(args[1], args[2], PK, 479, 13, 0)
	if err != nil {
		fmt.Println("<2>")
		return
	}

	//fmt.Println(reply.PublicKey)

	//fmt.Println(reply.Content)

}

func EncryptMessage(key []byte, message string) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func enc(args []string) {

	EncryptFile([]byte(*secretKey), args[1], args[2])

}

func EncryptFile(key []byte, filename string, out string) {

	f, err := os.Open(filename)
	if err != nil {

	}

	content, err := io.ReadAll(f)
	if err != nil {

	}

	f.Close()

	enc, err := EncryptMessage(key, string(content))
	if err != nil {

	}

	outFile, err := os.Create(out)
	if err != nil {

	}

	outFile.Write([]byte(enc))

	outFile.Close()

}

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func SendRequest(address string, filename string, PK int64, prime int64, generator int64, s int64) error {

	args := Args{filename, PK, prime, generator, s}
	reply := Reply{}
	fmt.Println("GENERATOR: ", generator)
	fmt.Println("PRIME: ", prime)

	ok := call(address, "Node.HandleRequest", &args, &reply)
	if !ok {
		fmt.Println("Error requesting")
		return nil
	}

	secret := int64(math.Mod(math.Pow(float64(reply.PublicKey), float64(*SK)), float64(prime)))
	fmt.Println("PK_A: ", reply.PublicKey)
	fmt.Println("PK_A: ", *SK)
	fmt.Println("PK_A: ", prime)
	fmt.Println("Secret: ", secret)

	secretExt := strconv.FormatInt(secret, 10)
	for len(secretExt) < 32 {
		secretExt = secretExt + secretExt
	}
	secretExt = secretExt[:32]

	args = Args{filename, PK, prime, generator, s}
	reply = Reply{}

	ok = call(address, "Node.GetKey", &args, &reply)
	if !ok {
		fmt.Println("Error requesting")
		return nil
	}
	fmt.Println(reply.EncKey)

	dKey, err := DecryptMessage([]byte(secretExt), reply.EncKey)
	if err != nil {
		fmt.Println("Error decrypting ", err)
		return nil
	}

	fmt.Println(dKey)

	args = Args{filename, PK, prime, generator, s}
	reply = Reply{}

	ok = call(address, "Node.GetFile", &args, &reply)
	if !ok {
		fmt.Println("Error requesting")
		return nil
	}

	text, err := DecryptMessage([]byte(dKey), reply.Content)
	if err != nil {
		fmt.Println("Error decrypting ", err)
		return nil

	}
	fmt.Println(text)
	return nil

}

func (n *Node) GetKey(args *Args, reply *Reply) error {

	secret := int64(math.Mod(math.Pow(float64(n.PK_B), float64(*SK)), float64(args.Prime)))
	fmt.Println("Secret: ", secret)

	secretExt := strconv.FormatInt(secret, 10)
	for len(secretExt) < 32 {
		secretExt = secretExt + secretExt
	}
	secretExt = secretExt[:32]

	fmt.Println(secretExt)

	eKey, err := EncryptMessage([]byte(secretExt), *secretKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	dKey, err := DecryptMessage([]byte(secretExt), eKey)
	if err != nil {
		fmt.Println("Error decrypting ", err)
		return nil
	}

	fmt.Println(eKey, dKey)

	reply.EncKey = eKey

	return nil
}

func (n *Node) GetFile(args *Args, reply *Reply) error {

	f, err := os.Open(args.Filename)
	if err != nil {
		return nil
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return nil
	}

	reply.Content = string(content)
	return nil
}

func (n *Node) HandleRequest(args *Args, reply *Reply) error {

	//filename := args.Filename
	generator = args.Generator
	prime = args.Prime

	n.PK_B = args.PublicKey
	fmt.Println("PK_B: ", n.PK_B)
	fmt.Println("GENERATOR: ", generator)
	fmt.Println("PRIME: ", prime)

	ret := math.Mod(math.Pow(float64(generator), float64(*SK)), float64(prime))
	fmt.Println("PK: ", ret)

	reply.PublicKey = int64(ret)

	return nil
}

func (n *Node) server() {
	rpc.Register(n)
	rpc.HandleHTTP()
	host := *address + ":" + strconv.Itoa(*port)

	l, err := net.Listen("tcp", host)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	go http.Serve(l, nil)
	fmt.Println("Created server at: ", host)
}

func call(rpcname string, method string, args interface{}, reply interface{}) bool {
	c, err := rpc.DialHTTP("tcp", rpcname)
	if err != nil {
		log.Fatal("dialing:", err)
	}
	defer c.Close()

	err = c.Call(method, args, reply)
	if err == nil {
		return true
	}

	fmt.Println(err)
	return false
}
