package model

import "errors"

// ErrNoTools prevents an empty discovery result from being reported as a clean scan.
var ErrNoTools = errors.New("scan incomplete: no tools discovered; a security grade cannot be assigned")
