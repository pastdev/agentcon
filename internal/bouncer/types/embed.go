// Package types holds bouncer.d.ts, the TypeScript API for filters.
// Copy that file into a ts/ tree for editor completion.
package types

import _ "embed"

//go:embed bouncer.d.ts
var BouncerDTS []byte
