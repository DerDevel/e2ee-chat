package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type CryptoManager struct {
	privateKey []byte
	publicKey  []byte
	sharedKey  []byte
}

type ChatData struct {
	Nickname string `json:"nick"`
	Text     string `json:"text"`
}

func NewCryptoManager() *CryptoManager {
	cm := &CryptoManager{}
	cm.GenerateKeys()
	return cm
}

func (c *CryptoManager) GenerateKeys() {
	c.privateKey = make([]byte, 32)
	rand.Read(c.privateKey)
	pub, _ := curve25519.X25519(c.privateKey, curve25519.Basepoint)
	c.publicKey = pub
}

func (c *CryptoManager) GetPublicKeyHex() string {
	return hex.EncodeToString(c.publicKey)
}

func (c *CryptoManager) DeriveSharedKey(peerPubKeyHex string) error {
	peerPubKey, err := hex.DecodeString(peerPubKeyHex)
	if err != nil {
		return err
	}
	shared, err := curve25519.X25519(c.privateKey, peerPubKey)
	if err != nil {
		return err
	}
	c.sharedKey = shared
	return nil
}

// НОВАЯ ФУНКЦИЯ: Генерация кода безопасности (защита от MITM)
func (c *CryptoManager) GenerateSafetyCode(peerPubKeyHex string) (string, error) {
	peerPubKey, err := hex.DecodeString(peerPubKeyHex)
	if err != nil {
		return "", err
	}

	// Создаем слайс из двух ключей
	keys := [][]byte{c.publicKey, peerPubKey}
	// Сортируем, чтобы оба клиента (А и Б) получили одинаковый порядок ключей
	sort.Slice(keys, func(i, j int) bool {
		return string(keys[i]) < string(keys[j])
	})

	// Хэшируем оба ключа
	h := sha256.New()
	h.Write(keys[0])
	h.Write(keys[1])
	hash := h.Sum(nil)

	// Берем первые 8 байт хэша и конвертируем в 12-значное число
	num := binary.BigEndian.Uint64(hash[:8]) % 1000000000000
	return fmt.Sprintf("%04d %04d %04d", num/100000000, (num/10000)%10000, num%10000), nil
}

func (c *CryptoManager) Encrypt(nick, text string) ([]byte, []byte, error) {
	if c.sharedKey == nil {
		return nil, nil, errors.New("ключ не сгенерирован")
	}

	aead, err := chacha20poly1305.New(c.sharedKey)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	data := ChatData{Nickname: nick, Text: text}
	jsonData, _ := json.Marshal(data)

	ciphertext := aead.Seal(nil, nonce, jsonData, nil)
	return nonce, ciphertext, nil
}

func (c *CryptoManager) Decrypt(nonce, ciphertext []byte) (string, string, error) {
	if c.sharedKey == nil {
		return "", "", errors.New("ключ не сгенерирован")
	}

	aead, err := chacha20poly1305.New(c.sharedKey)
	if err != nil {
		return "", "", err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", "", err
	}

	var data ChatData
	json.Unmarshal(plaintext, &data)

	return data.Nickname, data.Text, nil
}
