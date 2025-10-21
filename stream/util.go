package stream

import "io"

func toCloser(v any) io.Closer {
	if c, ok := v.(io.Closer); ok {
		return c
	}
	return nil
}
