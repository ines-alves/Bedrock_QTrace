package fixtures

import (
	mrand "math/rand"
)

func jitter() int {
	return mrand.Intn(100)
}
