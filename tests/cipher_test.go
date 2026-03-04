package tests

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/debkalyanmohanty/timebasedcipher-go/cipher"
)

const SECRET = "d206f482e53df3c9fe30c0f5ae7edae879999dfc9a6164bad75cb3e419b63eca"
const INTERVAL = int64(60)
const ITERATIONS = 100

var payload = map[string]interface{}{
	"message": "hello world",
	"numbers": generateNumbers(1000),
}

func generateNumbers(n int) []int {

	arr := make([]int, n)

	for i := 0; i < n; i++ {
		arr[i] = i
	}

	return arr
}

func TestBasicEncryptDecrypt(t *testing.T) {

	fmt.Println("\n🔐 1️⃣ Basic encrypt/decrypt")

	token, err := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Token:", token)

	data, err := cipher.Decrypt[map[string]interface{}](token, SECRET, INTERVAL, nil)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Decrypted Data:", data)

	if data["message"] != payload["message"] {
		t.Fatal("payload mismatch")
	}

	fmt.Println("✔ Passed")
}

func TestWrongSecretFails(t *testing.T) {

	fmt.Println("\n2️⃣ Wrong secret failure")

	token, _ := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

	_, err := cipher.Decrypt[map[string]interface{}](token, "wrong-secret", INTERVAL, nil)

	if err == nil {
		t.Fatal("expected failure")
	}

	fmt.Println("✔ Passed")
}

func TestRandomIVProducesDifferentTokens(t *testing.T) {

	fmt.Println("\n3️⃣ Random IV uniqueness")

	t1, _ := cipher.Encrypt(payload, SECRET, INTERVAL, nil)
	t2, _ := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

	fmt.Println("Token 1:", t1)
	fmt.Println("Token 2:", t2)

	if t1 == t2 {
		t.Fatal("tokens should differ")
	}

	fmt.Println("✔ Passed")
}

func TestTamperDetection(t *testing.T) {

	fmt.Println("\n4️⃣ Tamper detection")

	token, _ := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

	tampered := token[:len(token)-2] + "aa"

	fmt.Println("Tampered Token:", tampered)

	_, err := cipher.Decrypt[map[string]interface{}](tampered, SECRET, INTERVAL, nil)

	if err == nil {
		t.Fatal("tampered token should fail")
	}

	fmt.Println("✔ Passed")
}

func TestRotationInvalidation(t *testing.T) {

	fmt.Println("\n5️⃣ Rotation invalidation")

	token, _ := cipher.Encrypt(payload, SECRET, 2, nil)

	fmt.Println("Token:", token)
	fmt.Println("Waiting for rotation...")

	time.Sleep(4 * time.Second)

	_, err := cipher.Decrypt[map[string]interface{}](token, SECRET, 2, nil)

	if err == nil {
		t.Fatal("token should fail after rotation")
	}

	fmt.Println("✔ Passed")
}

func TestReplayProtection(t *testing.T) {

	fmt.Println("\n6️⃣ Replay protection")

	token, _ := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

	fmt.Println("Token:", token)

	_, err := cipher.Decrypt[map[string]interface{}](token, SECRET, INTERVAL, nil)

	if err != nil {
		t.Fatal(err)
	}

	_, err = cipher.Decrypt[map[string]interface{}](token, SECRET, INTERVAL, nil)

	if err == nil {
		t.Fatal("replay should fail")
	}

	fmt.Println("✔ Passed")
}

func TestPerformanceBenchmark(t *testing.T) {

	fmt.Println("\n7️⃣ Performance Benchmark")

	var totalEnc time.Duration
	var totalDec time.Duration

	for i := 0; i < ITERATIONS; i++ {

		start := time.Now()

		token, err := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

		if err != nil {
			t.Fatal(err)
		}

		totalEnc += time.Since(start)

		start = time.Now()

		_, err = cipher.Decrypt[map[string]interface{}](token, SECRET, INTERVAL, nil)

		if err != nil {
			t.Fatal(err)
		}

		totalDec += time.Since(start)
	}

	avgEnc := totalEnc / ITERATIONS
	avgDec := totalDec / ITERATIONS

	fmt.Println("Iterations:", ITERATIONS)
	fmt.Println("Average Encrypt:", avgEnc)
	fmt.Println("Average Decrypt:", avgDec)
}

func TestLargePayload(t *testing.T) {

	fmt.Println("\n8️⃣ Large payload test")

	bigPayload := map[string]string{
		"data": strings.Repeat("x", 1024*500),
	}

	token, err := cipher.Encrypt(bigPayload, SECRET, INTERVAL, nil)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Large Token Size:", len(token))

	data, err := cipher.Decrypt[map[string]string](token, SECRET, INTERVAL, nil)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Payload Size:", len(data["data"]))

	if len(data["data"]) != len(bigPayload["data"]) {
		t.Fatal("large payload mismatch")
	}

	fmt.Println("✔ Passed")
}

func TestConcurrency(t *testing.T) {

	fmt.Println("\n9️⃣ Concurrency test")

	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {

		wg.Add(1)

		go func(i int) {

			defer wg.Done()

			token, err := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

			if err != nil {
				t.Error(err)
				return
			}

			data, err := cipher.Decrypt[map[string]interface{}](token, SECRET, INTERVAL, nil)

			if err != nil {
				t.Error(err)
				return
			}

			if data["message"] != payload["message"] {
				t.Error("payload mismatch")
			}

		}(i)
	}

	wg.Wait()

	fmt.Println("✔ Passed")
}

func TestTokenFormat(t *testing.T) {

	fmt.Println("\n🔟 Token format test")

	token, err := cipher.Encrypt(payload, SECRET, INTERVAL, nil)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Token:", token)

	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		t.Fatal("invalid token format")
	}

	if parts[0] != "v1" {
		t.Fatal("invalid version")
	}

	fmt.Println("✔ Passed")
}
