package Stark

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"strings"
)

type Channel struct {
	state string
	proof []string
}

func NewChannel() *Channel {
	stateHex := "0"
	return &Channel{
		state: stateHex,
		proof: []string{},
	}
}

func (c *Channel) Send(s string) {
	input := c.state + s
	hash := sha256.Sum256([]byte(input))
	c.state = hex.EncodeToString(hash[:])

	pc, _, _, _ := runtime.Caller(0)
	funcName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(funcName, ".")
	callerName := parts[len(parts)-1]
	c.proof = append(c.proof, fmt.Sprintf("%s:%s", callerName, s))
}

func (c *Channel) ReceiveRandomInt(min, max *big.Int) *big.Int {

	stateInt, _ := new(big.Int).SetString(c.state, 16)

	rangeSize := new(big.Int).Sub(max, min)
	rangeSize.Add(rangeSize, big.NewInt(1))

	modResult := new(big.Int).Mod(stateInt, rangeSize)
	result := new(big.Int).Add(modResult, min)
	hash := sha256.Sum256([]byte(c.state))
	c.state = hex.EncodeToString(hash[:])

	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(funcName, ".")
	callerName := parts[len(parts)-1]

	c.proof = append(c.proof, fmt.Sprintf("%s:%s", callerName, result.String()))

	return result
}

func (c *Channel) ReceiveRandomFieldElement() FiniteFieldElement {
	min := big.NewInt(0)
	max := new(big.Int).Sub(DefaultFieldSize, big.NewInt(1))

	num := c.ReceiveRandomInt(min, max)
	randomFieldElement := DefaultField.NewFieldElement(num)
	return randomFieldElement
}
