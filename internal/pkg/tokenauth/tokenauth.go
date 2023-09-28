package tokenauth

import "net/http"

// Injector is accessed by Injector_RoundTrip to inject an
// Authorization Bearer token on every HTTP request.
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

// Implements the http.RoundTripper interface injecting an
// Authorization: Bearer token header with every http request.
// Example:
//
//	c := http.Client{}
//	c.Timeout = 10 * time.Second
//	c.Transport = &authtoken.Injector{Token: "secret", OriginalTransport: c.Transport}
func (t *Injector) RoundTrip(r *http.Request) (*http.Response, error) {
	// Inject Authorization header in all requests
	r.Header.Set("Authorization", "Bearer "+t.Token)
	// Call the original RoundTripper and return
	return t.roundtripper().RoundTrip(r)
}
