package mcpintegrity

import (
	"sync"
	"time"
)

// maxTrackedTools bounds the behaviour map so a server that mints tool names
// cannot grow it without limit; tools past the bound are simply not tracked.
const maxTrackedTools = 10000

// minSamplesForSize is how many calls establish a tool's normal argument size.
const minSamplesForSize = 20

type toolBehavior struct {
	windowStart time.Time
	windowCount int
	samples     int
	avgBytes    float64
}

// behaviorTracker keeps per-tool call rate and argument-size baselines.
type behaviorTracker struct {
	mu    sync.Mutex
	tools map[string]*toolBehavior
}

func newBehaviorTracker() *behaviorTracker {
	return &behaviorTracker{tools: map[string]*toolBehavior{}}
}

type behaviorVerdict struct {
	rateExceeded bool
	oversize     bool
	count        int
	avg          float64
}

// observe records one call and reports whether it breaks a configured limit.
// The key is client+"\x00"+tool.
func (b *behaviorTracker) observe(key string, argBytes int, now time.Time, maxPerMin int, sizeFactor float64) behaviorVerdict {
	b.mu.Lock()
	defer b.mu.Unlock()
	tb := b.tools[key]
	if tb == nil {
		if len(b.tools) >= maxTrackedTools {
			return behaviorVerdict{}
		}
		tb = &toolBehavior{windowStart: now}
		b.tools[key] = tb
	}
	if now.Sub(tb.windowStart) >= time.Minute {
		tb.windowStart, tb.windowCount = now, 0
	}
	tb.windowCount++
	v := behaviorVerdict{count: tb.windowCount, avg: tb.avgBytes}
	if maxPerMin > 0 && tb.windowCount > maxPerMin {
		v.rateExceeded = true
	}
	if sizeFactor > 0 && tb.samples >= minSamplesForSize && argBytes > 1024 &&
		float64(argBytes) > sizeFactor*tb.avgBytes {
		// An anomalous call is not folded into the average, so a burst of
		// oversize calls cannot teach the baseline that they are normal.
		v.oversize = true
		return v
	}
	tb.samples++
	tb.avgBytes += (float64(argBytes) - tb.avgBytes) / float64(min(tb.samples, 200))
	return v
}
