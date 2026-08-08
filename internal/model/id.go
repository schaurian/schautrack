package model

import (
	"math"
	"strconv"
)

// MaxID is the largest value any id in this schema can hold.
//
// Every id column is SERIAL or INTEGER — Postgres int4 — including users.id
// and every table that references it. pgx encodes a Go int into that column as
// int4, so a larger value is not a row that does not exist: it is an encoding
// error from the driver, which surfaces as a 500.
const MaxID = math.MaxInt32

// ParseID parses a user-supplied identifier, rejecting anything that is not a
// positive value an int4 column can hold.
//
// The bound is the point. strconv.Atoi returns a 64-bit int on every platform
// this runs on, so "34359738367" parses cleanly and passes a `> 0` check, then
// reaches the database and fails there with
//
//	unable to encode 34359738367 into binary format for int4 (OID 23)
//
// turning what should be a 404 for a nonexistent row into a 500 with a stack
// of driver internals in the log. Found by the OpenAPI contract fuzzer, which
// generates exactly this kind of boundary value.
func ParseID(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > MaxID {
		return 0, false
	}
	return n, true
}
