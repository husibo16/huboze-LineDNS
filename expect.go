package main

import (
	"io"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"
)

// expecter is a tiny pexpect-like helper on top of an SSH shell channel.
type expecter struct {
	w      io.Writer
	mu     sync.Mutex
	buf    string
	eof    bool
	notify chan struct{}
	// Before holds the text preceding the last match (or the whole buffer on EOF/TIMEOUT).
	Before string
}

const (
	expEOF     = -1
	expTimeout = -2
)

func newExpecter(r io.Reader, w io.Writer) *expecter {
	e := &expecter{w: w, notify: make(chan struct{}, 1)}
	go e.readLoop(r)
	return e
}

func (e *expecter) readLoop(r io.Reader) {
	chunk := make([]byte, 8192)
	var pending []byte
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			pending = append(pending, chunk[:n]...)
			// keep an incomplete trailing UTF-8 sequence for the next read
			cut := len(pending)
			for i := 1; i <= 3 && i <= len(pending); i++ {
				b := pending[len(pending)-i]
				if b&0xC0 != 0x80 { // lead byte or ASCII
					if !utf8.FullRune(pending[len(pending)-i:]) {
						cut = len(pending) - i
					}
					break
				}
			}
			text := decodeIgnore(pending[:cut])
			pending = append([]byte(nil), pending[cut:]...)
			e.mu.Lock()
			e.buf += text
			e.mu.Unlock()
			e.signal()
		}
		if err != nil {
			e.mu.Lock()
			if len(pending) > 0 {
				e.buf += decodeIgnore(pending)
			}
			e.eof = true
			e.mu.Unlock()
			e.signal()
			return
		}
	}
}

// decodeIgnore mimics Python's decode("utf-8", errors="ignore").
func decodeIgnore(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r != utf8.RuneError || size > 1 {
			out = append(out, r)
		}
		b = b[size:]
	}
	return string(out)
}

func (e *expecter) signal() {
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

func (e *expecter) Send(s string) { _, _ = io.WriteString(e.w, s) }

// SendLine sends the text followed by "\n" (pexpect's default linesep).
func (e *expecter) SendLine(s string) { e.Send(s + "\n") }

// Expect waits for the earliest match of any pattern. Returns the pattern
// index, expEOF or expTimeout. On a match the buffer is consumed up to the
// end of the match; on timeout the buffer is kept (like pexpect).
func (e *expecter) Expect(timeout time.Duration, patterns ...*regexp.Regexp) int {
	deadline := time.Now().Add(timeout)
	for {
		e.mu.Lock()
		best, bestStart, bestEnd := -1, -1, -1
		for i, p := range patterns {
			loc := p.FindStringIndex(e.buf)
			if loc != nil && (bestStart < 0 || loc[0] < bestStart) {
				best, bestStart, bestEnd = i, loc[0], loc[1]
			}
		}
		if best >= 0 {
			e.Before = e.buf[:bestStart]
			e.buf = e.buf[bestEnd:]
			e.mu.Unlock()
			return best
		}
		if e.eof {
			e.Before = e.buf
			e.buf = ""
			e.mu.Unlock()
			return expEOF
		}
		e.mu.Unlock()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			e.mu.Lock()
			e.Before = e.buf
			e.mu.Unlock()
			return expTimeout
		}
		t := time.NewTimer(remaining)
		select {
		case <-e.notify:
		case <-t.C:
		}
		t.Stop()
	}
}
