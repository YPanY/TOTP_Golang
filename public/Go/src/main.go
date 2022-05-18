package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"syscall/js"
	"time"
)

func addFunction(this js.Value, p []js.Value) interface{} {
	sum := p[0].Int() + p[1].Int()
	return js.ValueOf(sum)
}

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("TOTP", js.FuncOf(TOTPPortfolio))
	<-c
}

func TOTP(k string, t0, validSec, digit int) string {
	t := GetTime(t0, validSec)
	totp := DT(HMACSHA1(k, uint64(t)), digit)
	return totp
}

func TOTPPortfolio(this js.Value, p []js.Value) interface{} {
	t := GetTime(0, 30)
	totp := DT(HMACSHA1(p[0].String(), uint64(t)), 8)
	return js.ValueOf(totp)
}

func GetTime(t0, timeStep int) int {
	return (int(time.Now().Unix()) - t0) / timeStep
}

func GetTimeForTest(time, t0, timeStep int) int {
	return (time - t0) / timeStep
}

func HMACSHA1(key string, count uint64) []byte {
	countByte := make([]byte, 8)
	binary.BigEndian.PutUint64(countByte, count)
	keyByte := []byte(key)
	mac := hmac.New(sha1.New, keyByte)
	mac.Write(countByte)
	return mac.Sum(nil)
}

func HMACSHA256(key string, count uint64) []byte {
	countByte := make([]byte, 8)
	binary.BigEndian.PutUint64(countByte, count)
	keyByte := []byte(key)
	mac := hmac.New(sha256.New, keyByte)
	mac.Write(countByte)
	return mac.Sum(nil)
}

func HMACSHA256ForTest(k string, time, digit int) string {
	totp := DT(HMACSHA256(k, uint64(time)), digit)
	return totp
}

func DT(hm []byte, digit int) string {
	offset := hm[len(hm)-1] & 0x0F
	truncatedHex := hm[offset : offset+4]
	truncatedInt := int(binary.BigEndian.Uint32(truncatedHex) & 0x7FFFFFFF)
	truncatedString := strconv.Itoa(truncatedInt)
	return truncatedString[len(truncatedString)-digit:]
}
