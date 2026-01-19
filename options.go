package jwks

import "time"

func WithInterval(interval time.Duration) Option {
	return func(j *JwksAuthority) {
		j.refreshInterval = interval
	}
}
