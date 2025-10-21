package tokenauth

import "net/http"

// Injector wraps an http.RoundTripper to inject an Authorization Bearer token
// into every HTTP request.
type Injector struct {
	Token             string
	OriginalTransport http.RoundTripper
}

// roundtripper returns the original http.RoundTripper (Transport) or
// http.DefaultTransport if original was nil.
func (t *Injector) roundtripper() http.RoundTripper {
	if t.OriginalTransport != nil {
		return t.OriginalTransport
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper, injecting an Authorization: Bearer
// token header into every outbound HTTP request. Example:
//
//	c := http.Client{}
//	c.Timeout = 10 * time.Second
//	c.Transport = &tokenauth.Injector{Token: "secret", OriginalTransport: c.Transport}
func (t *Injector) RoundTrip(r *http.Request) (*http.Response, error) {
	// Inject Authorization header in all requests
	r.Header.Set("Authorization", "Bearer "+t.Token)
	// Call the original RoundTripper and return
	return t.roundtripper().RoundTrip(r)
}
