package jsfilter

import (
	"crypto/rand"
	"encoding/hex"
	"maps"
	"net/http"

	"github.com/dop251/goja"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// placeholder backs placeholder(name). It returns a new one-time string
// for the credential, which Bouncer replaces only in this run's
// subrequests, and only where the request may use the credential.
func (i *instance) placeholder(call goja.FunctionCall) goja.Value {
	vm := i.vm
	name, ok := call.Argument(0).Export().(string)
	if !ok || name == "" {
		panic(vm.NewTypeError("placeholder(name) requires a credential name"))
	}
	if i.cur == nil || i.placeholders == nil {
		panic(vm.NewTypeError("placeholder() can only be called while handling a request"))
	}
	if check := i.f.opts.Env.Placeholder; check != nil {
		err := check(name)
		if err != nil {
			panic(vm.NewTypeError("placeholder: " + err.Error()))
		}
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := config.Placeholder(name) + "-" + hex.EncodeToString(b[:])
	i.placeholders[v] = name
	return vm.ToValue(v)
}

// subrequest backs subrequest(init). It sends an HTTP request through
// Bouncer's policy for the current request's session and resolves with the
// response. It rejects only when there is no response.
func (i *instance) subrequest(call goja.FunctionCall) goja.Value {
	vm := i.vm
	req := i.cur
	if req == nil {
		panic(vm.NewTypeError("subrequest() can only be called while handling a request"))
	}
	send := i.f.opts.Env.Subrequest
	if send == nil {
		panic(vm.NewTypeError("subrequest() is not configured"))
	}
	spec := i.subrequestSpec(call.Argument(0))
	return i.blocking(func() (goja.Value, error) {
		caller := chain.SubrequestCaller{Filter: i.f.name, ID: i.f.opts.ID, Placeholders: maps.Clone(i.placeholders)}
		resp, u, err := send(req, caller, spec)
		if err != nil {
			return nil, err
		}
		v := i.wrapResponse(resp)
		// wrapResponse gave the response a body. It is closed when this run
		// ends unless the filter returns this response.
		i.subBodies = append(i.subBodies, resp.Body)
		v.ToObject(vm).Set("url", u.String())
		return v, nil
	})
}

// subrequestSpec reads subrequest()'s init object. A malformed one throws.
func (i *instance) subrequestSpec(arg goja.Value) chain.SubrequestSpec {
	vm := i.vm
	o, ok := arg.(*goja.Object)
	if !ok {
		panic(vm.NewTypeError("subrequest(init) requires an object with a url"))
	}
	get := func(name string) goja.Value {
		v := o.Get(name)
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
			return nil
		}
		return v
	}
	var spec chain.SubrequestSpec
	u, ok := exportString(get("url"))
	if !ok || u == "" {
		panic(vm.NewTypeError("subrequest: url must be a non-empty string"))
	}
	spec.URL = u
	if v := get("method"); v != nil {
		m, ok := exportString(v)
		if !ok {
			panic(vm.NewTypeError("subrequest: method must be a string"))
		}
		spec.Method = m
	}
	spec.Header = http.Header{}
	if v := get("headers"); v != nil {
		ho, ok := v.(*goja.Object)
		if !ok {
			panic(vm.NewTypeError("subrequest: headers must be an object"))
		}
		for _, k := range ho.Keys() {
			hv := ho.Get(k)
			if hv == nil || goja.IsUndefined(hv) || goja.IsNull(hv) {
				continue
			}
			spec.Header.Set(k, hv.String())
		}
	}
	if v := get("body"); v != nil {
		switch v.Export().(type) {
		case string, []byte, goja.ArrayBuffer:
		default:
			if spec.Header.Get("Content-Type") == "" {
				spec.Header.Set("Content-Type", "application/json")
			}
		}
		b, err := toBytes(i, v)
		if err != nil {
			panic(vm.NewTypeError("subrequest: body: " + err.Error()))
		}
		spec.Body = b
	}
	if v := get("redirect"); v != nil {
		switch r, _ := exportString(v); r {
		case "follow":
		case "manual":
			spec.Manual = true
		default:
			panic(vm.NewTypeError(`subrequest: redirect must be "follow" or "manual"`))
		}
	}
	if v := get("timeout"); v != nil {
		d := parseTTL(v)
		if d <= 0 {
			panic(vm.NewTypeError("subrequest: timeout must be a positive duration"))
		}
		spec.Timeout = d
	}
	return spec
}

func exportString(v goja.Value) (string, bool) {
	if v == nil {
		return "", false
	}
	s, ok := v.Export().(string)
	return s, ok
}

// closeSubBodies closes the bodies of this run's subrequest responses,
// except keep, which the filter returned as its own response.
func (i *instance) closeSubBodies(keep *chain.Response) {
	for _, b := range i.subBodies {
		if keep != nil && keep.Body == b {
			continue
		}
		_ = b.Close()
	}
	i.subBodies = nil
}
