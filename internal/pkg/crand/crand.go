/* crypto/rand using math/rand as interface (C) Stefan Nilsson
 * https://yourbasic.org/golang/crypto-rand-int/
 * Modified by SA6MWA with a mutex lock to be goroutine-safe and packaged as
 * github.com/sa6mwa/gotostash/pkg/crand
 */

package crand

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"sync"
)

// There is no seeding required in this implementation so no need to export a
// new source like with math/rand, but this will have to change if we add
// another PRNG. The API should then be backward compatible with the
// crypto/rand implementation as default.
var gsrc = cryptoRandSource{&sync.Mutex{}}
var gr = rand.New(gsrc)

// Not sure if we want to export some of these structs in the future, but
// currently the package only exports the primary functionality.
type cryptoRandSource struct {
	*sync.Mutex
}

func (s cryptoRandSource) Seed(seed int64) {
	// no seeding, already handled by the OS
}
func (s cryptoRandSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}
func (s cryptoRandSource) Uint64() (v uint64) {
	s.Lock()
	err := binary.Read(cryptoRand.Reader, binary.BigEndian, &v)
	s.Unlock()
	if err != nil {
		panic(err)
	}
	return // automatically implies that v is returned
}

func (s cryptoRandSource) Read(p []byte) (n int, err error) {
	s.Lock()
	err = binary.Read(cryptoRand.Reader, binary.BigEndian, &p)
	s.Unlock()
	return len(p), err
}

func (s cryptoRandSource) ReadRunes(p []rune) (n int, err error) {
	s.Lock()
	err = binary.Read(cryptoRand.Reader, binary.BigEndian, &p)
	s.Unlock()
	return len(p), err
}

// Seed is provided for math/rand compatibility; it is a no-op because entropy
// comes from crypto/rand.
func Seed(seed int64) { gsrc.Seed(seed) }

// Int63 returns a non-negative 63-bit integer derived from the crypto-backed source.
func Int63() int64 { return gsrc.Int63() }

// Uint32 returns a pseudo-random 32-bit value using the crypto-seeded PRNG.
func Uint32() uint32 { return gr.Uint32() }

// Uint64 returns a pseudo-random 64-bit value using crypto/rand as the seed.
func Uint64() uint64 { return gsrc.Uint64() }

// Int31 returns a non-negative 31-bit integer using the crypto-seeded PRNG.
func Int31() int32 { return gr.Int31() }

// Int returns a non-negative pseudo-random int using the crypto-seeded PRNG.
func Int() int { return gr.Int() }

// Int63n returns a pseudo-random 63-bit integer in [0, n) using the crypto-seeded PRNG.
func Int63n(n int64) int64 { return gr.Int63n(n) }

// Int31n returns a pseudo-random 31-bit integer in [0, n) using the crypto-seeded PRNG.
func Int31n(n int32) int32 { return gr.Int31n(n) }

// Intn returns a pseudo-random integer in [0, n) using the crypto-seeded PRNG.
func Intn(n int) int { return gr.Intn(n) }

// Float64 returns a pseudo-random float64 in [0.0, 1.0) using the crypto-seeded PRNG.
func Float64() float64 { return gr.Float64() }

// Float32 returns a pseudo-random float32 in [0.0, 1.0) using the crypto-seeded PRNG.
func Float32() float32 { return gr.Float32() }

// Perm returns a pseudo-random permutation of the numbers [0, n) using the crypto-seeded PRNG.
func Perm(n int) []int { return gr.Perm(n) }

// Shuffle pseudo-randomly permutes n elements using the supplied swap function.
func Shuffle(n int, swap func(i, j int)) { gr.Shuffle(n, swap) }

// Read fills p with cryptographically sourced random data.
func Read(p []byte) (n int, err error) { return gsrc.Read(p) }

// ReadRunes fills p with cryptographically sourced random runes.
func ReadRunes(p []rune) (n int, err error) { return gsrc.ReadRunes(p) }

// NormFloat64 returns a normally distributed float64 using the crypto-seeded PRNG.
func NormFloat64() float64 { return gr.NormFloat64() }

// ExpFloat64 returns an exponentially distributed float64 using the crypto-seeded PRNG.
func ExpFloat64() float64 { return gr.ExpFloat64() }
