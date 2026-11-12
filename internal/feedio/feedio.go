// Package feedio holds the I/O discipline shared by the feed generators
// (iptoasn, mm-dbip, mm-geolite2-asn, rir-country): a generator succeeds only
// when it has published a complete file, not merely when it exited 0.
//
// It provides three pieces:
//
//   - [Create] / [Output]: an atomic output file. Bytes go to a hidden temp file
//     in the target's directory; [Output.Commit] fsyncs and renames it over the
//     target, [Output.Abort] discards it. A reader of the target therefore sees
//     the previous complete file or the new complete file, never a prefix.
//   - [Fetch]: an HTTP GET whose body fails if no byte arrives for an idle
//     period. A large slow download keeps working; a stalled server does not
//     hang the run forever.
//   - [MaybeGunzip]: transparent gzip decoding that reports a corrupt stream as
//     an error instead of falling back to reading the compressed bytes as text.
//
// The package is stdlib only.
package feedio

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Output is a buffered, atomically published output file, or stdout.
// The zero value is not usable; get one from [Create].
type Output struct {
	bw     *bufio.Writer
	f      *os.File // temp file; nil when writing to stdout or a special file
	direct *os.File // an existing non-regular target written through (e.g. /dev/null)
	path   string   // final path (symlinks resolved); "" for stdout
	name   string   // path as given, for messages
	done   bool
}

// Create opens an output for path. The empty path and "-" mean stdout: no temp
// file is made and Commit only flushes. Otherwise a temp file named
// ".<base>.tmp-<random>" is created in the same directory as path (same
// filesystem, so the final rename is atomic; leading dot and ".tmp-" infix so a
// consumer glob such as *.cidr cannot match it). The target is not touched
// until Commit. A symlinked path is resolved first, so Commit replaces the file
// the link points at and the link survives. An existing target that is not a
// regular file (a device such as /dev/null, a FIFO) is written through
// directly, since a rename would replace it rather than write to it.
func Create(path string) (*Output, error) {
	if path == "" || path == "-" {
		return &Output{bw: bufio.NewWriter(os.Stdout)}, nil
	}
	name := path
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		d, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		return &Output{bw: bufio.NewWriter(d), direct: d, path: path, name: name}, nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	// CreateTemp is 0600; a published feed should look like one created with
	// os.Create, or like the file it replaces.
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &Output{bw: bufio.NewWriter(f), f: f, path: path, name: name}, nil
}

// Write implements io.Writer.
func (o *Output) Write(p []byte) (int, error) { return o.bw.Write(p) }

// Name describes the destination for messages: the final path, or "stdout".
func (o *Output) Name() string {
	if o.f == nil && o.direct == nil {
		return "stdout"
	}
	return o.name
}

// Commit publishes the output: flush, fsync, close, rename over the target, then
// fsync the directory so the rename itself survives a crash (best effort: a
// platform that cannot fsync a directory still has the file published). After
// Commit, or after a failed Commit, the temp file no longer exists. For stdout
// Commit only flushes.
func (o *Output) Commit() error {
	if o.done {
		return fmt.Errorf("feedio: output already finished")
	}
	o.done = true
	if err := o.bw.Flush(); err != nil {
		o.discard()
		return err
	}
	if o.direct != nil {
		return o.direct.Close()
	}
	if o.f == nil {
		return nil
	}
	if err := o.f.Sync(); err != nil {
		o.discard()
		return err
	}
	if err := o.f.Close(); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	if err := os.Rename(o.f.Name(), o.path); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	if d, err := os.Open(filepath.Dir(o.path)); err == nil {
		d.Sync() // best effort; unsupported on some platforms
		d.Close()
	}
	return nil
}

// Abort discards the output, removing the temp file and leaving any existing
// target untouched. It is a no-op after Commit or Abort, so it is safe to defer.
// For stdout it discards the unflushed buffer.
func (o *Output) Abort() {
	if o.done {
		return
	}
	o.done = true
	o.discard()
}

func (o *Output) discard() {
	if o.direct != nil {
		o.direct.Close()
	}
	if o.f != nil {
		o.f.Close()
		os.Remove(o.f.Name())
	}
}

// Fetch GETs url and returns its body. Dial, TLS handshake and response headers
// are each bounded by dial. The body has no overall deadline, but a Read that
// sees no bytes for idle fails with an error saying so, and the request is
// cancelled. The idle clock runs only while a Read is waiting on the network, so
// a slow consumer is never penalised. The proxy environment is honoured. A
// non-200 status is an error. An idle of zero or less disables the idle check
// (as a zero -timeout meant "no timeout" before this package existed).
// Keep-alives are off: each Fetch is a one-shot download, and pooled idle
// connections would otherwise stay open until the process exits.
func Fetch(url, userAgent string, dial, idle time.Duration) (io.ReadCloser, error) {
	client := &http.Client{Transport: &http.Transport{
		// A hand-built Transport has a nil Proxy, which silently ignores
		// HTTPS_PROXY/HTTP_PROXY/NO_PROXY — unlike http.DefaultTransport.
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: dial}).DialContext,
		TLSHandshakeTimeout:   dial,
		ResponseHeaderTimeout: dial,
		DisableKeepAlives:     true,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return &idleBody{rc: resp.Body, cancel: cancel, idle: idle}, nil
}

// idleBody enforces the idle deadline: a timer armed for each Read cancels the
// request if the Read has not returned within idle.
type idleBody struct {
	rc     io.ReadCloser
	cancel context.CancelFunc
	idle   time.Duration
	fired  atomic.Bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	if b.idle <= 0 {
		return b.rc.Read(p)
	}
	t := time.AfterFunc(b.idle, func() {
		b.fired.Store(true)
		b.cancel()
	})
	n, err := b.rc.Read(p)
	t.Stop()
	if err != nil && err != io.EOF && b.fired.Load() {
		err = fmt.Errorf("download stalled: no data for %s: %w", b.idle, err)
	}
	return n, err
}

func (b *idleBody) Close() error {
	err := b.rc.Close()
	b.cancel()
	return err
}

// MaybeGunzip returns a reader of r's decompressed content when r starts with
// the gzip magic bytes, and a reader of r itself otherwise. A gzip header that
// fails to parse is an error — never a silent fallback to reading the compressed
// bytes as text. Corruption later in the stream surfaces from Read.
func MaybeGunzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return zr, nil
	}
	return br, nil
}
