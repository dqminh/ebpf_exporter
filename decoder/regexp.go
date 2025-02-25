package decoder

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	lru "github.com/hashicorp/golang-lru/v2"
)

// Regexp is a decoder that only allows inputs matching regexp
type Regexp struct {
	cache       map[string]*regexp.Regexp
	outputCache *lru.Cache[string, []byte]
}

// Decode only allows inputs matching regexp
func (r *Regexp) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if conf.Regexps == nil {
		return nil, errors.New("no regexps defined in config")
	}
	inputStr := string(in)

	if r.cache == nil {
		r.cache = map[string]*regexp.Regexp{}
	}
	if conf.LruCacheSize > 0 && r.outputCache == nil {
		outputCache, err := lru.New[string, []byte](conf.LruCacheSize)
		if err != nil {
			return nil, err
		}
		r.outputCache = outputCache
	}

	for _, expr := range conf.Regexps {
		if _, ok := r.cache[expr]; !ok {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("error compiling regexp %q: %w", expr, err)
			}

			r.cache[expr] = compiled
		}

		if r.outputCache != nil {
			if v, ok := r.outputCache.Get(inputStr); ok {
				return v, nil
			}
		}

		matches := r.cache[expr].FindSubmatch(in)

		var output []byte
		if len(matches) == 2 {
			// First sub-match if present
			output = matches[1]
		} else if len(matches) == 1 {
			// General match
			output = matches[0]
		}
		if output != nil {
			if r.outputCache != nil {
				r.outputCache.Add(inputStr, output)
			}
			return output, nil
		}
	}

	return nil, ErrSkipLabelSet
}
