package wireray

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

type HTTPReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	parent   *TCPStream
	time     time.Time
}

func (h *HTTPReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *HTTPReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(h)
	for {
		if h.isClient {
			h.time = time.Now()
			req, err := http.ReadRequest(b)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				log.Println(fmt.Sprintf("HTTP-request", "HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err))
				continue
			}
			body, err := ioutil.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				log.Println(fmt.Sprintf("HTTP-request-body", "Got body err: %s\n", err))
				continue
			}
			defer req.Body.Close()
			h.parent.method = req.Method
			h.parent.url = req.URL.EscapedPath()

			hl := HTTPLog{
				id:        h.parent.id,
				time:      h.time,
				bodyBytes: s,
				method:    h.parent.method,
				url:       h.parent.url,
				header:    req.Header,
				isRequest: true,
			}

			if h.parent.dumpBody {
				hl.body = string(body)
			}

			h.parent.logch <- hl
		} else {
			res, err := http.ReadResponse(b, nil)
			h.time = time.Now()

			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				log.Println(fmt.Sprintf("HTTP-response", "HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err))
				continue
			}
			var reader io.ReadCloser
			switch res.Header.Get("Content-Encoding") {
			case "gzip":
				if h.parent.gunzip {
					reader, err = gzip.NewReader(res.Body)
					defer reader.Close()
				} else {
					reader = res.Body
				}
			default:
				reader = res.Body
			}
			body, err := ioutil.ReadAll(reader)
			s := len(body)

			if err != nil {
				log.Println(fmt.Sprintf("HTTP-response-body", "HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err))
				continue
			}

			defer res.Body.Close()
			hl := HTTPLog{
				id:        h.parent.id,
				time:      h.time,
				bodyBytes: s,
				method:    h.parent.method,
				url:       h.parent.url,
				status:    res.StatusCode,
				header:    res.Header,
				isRequest: false,
			}

			if h.parent.dumpBody {
				hl.body = string(body)
			}

			h.parent.logch <- hl
		}
	}
}
