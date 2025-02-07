package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

type KeyGenerator interface {
	GetKeyData() []byte
}

type KeyImporter interface {
	ImportKey(name string, keyData []byte) error
}

type DetKeyGen struct {
	keyID   string
	keyData []byte
}

type detRand struct {
	data   []byte
	offset int
}

func newRand(seed string) *detRand {
	hasher := sha256.New()
	hasher.Write([]byte(seed))
	initial := hasher.Sum(nil)

	data := make([]byte, 8192)
	copy(data, initial)

	for i := 32; i < len(data); i += 32 {
		hasher.Reset()
		hasher.Write(data[i-32 : i])
		copy(data[i:i+32], hasher.Sum(nil))
	}

	return &detRand{
		data:   data,
		offset: 0,
	}
}

func (r *detRand) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		hasher := sha256.New()
		hasher.Write(r.data)
		newData := hasher.Sum(nil)
		copy(r.data, newData)
		r.offset = 0
	}

	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func NewKeyGen(name string) (*DetKeyGen, error) {
	g := &DetKeyGen{}
	err := g.generateKey(name)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (g *DetKeyGen) GetKeyID() string {
	return g.keyID
}

func (g *DetKeyGen) GetKeyData() []byte {
	return g.keyData
}

func (g *DetKeyGen) generateKey(name string) error {
	reader := newRand(name)

	seedBytes := make([]byte, 32)
	_, err := reader.Read(seedBytes)
	if err != nil {
		return fmt.Errorf("failed to generate seed: %v", err)
	}

	privateKey := ed25519.NewKeyFromSeed(seedBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	libp2pPubKey, err := crypto.UnmarshalEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert to libp2p public key: %v", err)
	}

	peerID, err := peer.IDFromPublicKey(libp2pPubKey)
	if err != nil {
		return fmt.Errorf("failed to generate peer ID: %v", err)
	}

	cidStr, err := peer.ToCid(peerID).StringOfBase(multibase.Base36)
	if err != nil {
		return fmt.Errorf("failed to convert to CIDv1: %v", err)
	}

	g.keyID = cidStr

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to convert key format: %v", err)
	}

	var pemBuf bytes.Buffer
	err = pem.Encode(&pemBuf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to generate PEM data: %v", err)
	}

	g.keyData = pemBuf.Bytes()
	return nil
}

type IPFSKeyImporter struct {
	APIEndpoint string
}

func NewIPFSKeyImporter(endpoint string) *IPFSKeyImporter {
	return &IPFSKeyImporter{
		APIEndpoint: endpoint,
	}
}

func (i *IPFSKeyImporter) ImportKey(name string, keyData []byte) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	safeFilename := strings.ReplaceAll(name, "/", "_")
	safeFilename = strings.ReplaceAll(safeFilename, ":", "_")

	part, err := writer.CreateFormFile("file", safeFilename+".pem")
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = part.Write(keyData)
	if err != nil {
		return fmt.Errorf("failed to write key data: %v", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %v", err)
	}

	encodedKeyname := url.QueryEscape(name)
	url := fmt.Sprintf("%s/api/v0/key/import?arg=%s&format=pem-pkcs8-cleartext", i.APIEndpoint, encodedKeyname)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("IPFS API returned error status: %d, body: %s\nRequest URL: %s", resp.StatusCode, string(respBody), url)
	}

	return nil
}

type KeyService struct {
	generator KeyGenerator
	importer  KeyImporter
}

func NewKeyService(generator KeyGenerator, importer KeyImporter) *KeyService {
	return &KeyService{
		generator: generator,
		importer:  importer,
	}
}

func (s *KeyService) GenerateAndImportKey(name string) error {
	keyData := s.generator.GetKeyData()
	err := s.importer.ImportKey(name, keyData)
	if err != nil {
		return fmt.Errorf("failed to import key: %v", err)
	}

	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: keytest <keyname>")
		os.Exit(1)
	}
	keyname := os.Args[1]

	generator, err := NewKeyGen(keyname)
	if err != nil {
		fmt.Printf("Failed to create key generator: %v\n", err)
		os.Exit(1)
	}

	importer := NewIPFSKeyImporter("http://127.0.0.1:5001")
	service := NewKeyService(generator, importer)

	err = service.GenerateAndImportKey(keyname)
	if err != nil {
		fmt.Printf("Operation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s %s\n", generator.GetKeyID(), keyname)
}
