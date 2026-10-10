package fixtures

import (
	"fmt"
	"math/rand"
)

func token() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

func pick(n int) int {
	return rand.Intn(n)
}

func show() {
	fmt.Println(rand.Reader)
}
