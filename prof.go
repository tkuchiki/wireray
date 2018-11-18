package wireray

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sync"

	"sort"

	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/reassembly"
	"github.com/tkuchiki/gohttpstats"
	"github.com/tkuchiki/wireray/options"
)

type HTTPLog struct {
	id        string
	time      time.Time
	body      int
	method    string
	url       string
	status    int
	isRequest bool
	header    http.Header
}

type HTTPProfiler struct {
	sig    chan os.Signal
	stats  *httpstats.HTTPStats
	handle *pcap.Handle
	source *gopacket.PacketSource
	opts   *options.Options
	mu     sync.RWMutex
}

func NewHTTPProfiler(opts *options.Options, stats *httpstats.HTTPStats) *HTTPProfiler {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	return &HTTPProfiler{
		sig:   sig,
		opts:  opts,
		stats: stats,
	}
}

func (prof *HTTPProfiler) WritePcap(pfile string) error {
	f, err := os.Create(pfile)
	if err != nil {
		return err
	}

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(prof.opts.Uint32Snaplen(), layers.LinkTypeEthernet)
	defer f.Close()

	handle, err := openLive(prof.opts.Iface, prof.opts.Int32Snaplen())
	if err != nil {
		return err
	}
	defer handle.Close()
	bpffilter := bpfFilterWithPort(prof.opts.Port)
	log.Println(fmt.Sprintf("Using BPF filter %q", bpffilter))
	if err = handle.SetBPFFilter(bpffilter); err != nil {
		return fmt.Errorf("BPF filter error:", err)
	}
	log.Println("Starting to read packets")

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = prof.opts.Lazy
	source.NoCopy = true

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := packetSource.Packets()
capture:
	for {
		select {
		case packet := <-packets:
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		case <-prof.sig:
			log.Println("Stopping to read packets")
			break capture
		}

	}

	return nil
}

func (prof *HTTPProfiler) Profile() error {
	var handle *pcap.Handle
	var err error

	if prof.opts.Pcap != "" {
		handle, err = openOffline(prof.opts.Pcap)
	} else {
		handle, err = openLive(prof.opts.Iface, prof.opts.Int32Snaplen())
	}

	if err != nil {
		return err
	}
	defer handle.Close()

	bpffilter := bpfFilterWithPort(prof.opts.Port)
	log.Println(fmt.Sprintf("Using BPF filter %q", bpffilter))
	if err = handle.SetBPFFilter(bpffilter); err != nil {
		return fmt.Errorf("BPF filter error:", err)
	}

	source := newPacketSource(handle, prof.opts.Lazy)

	log.Println("Starting to read packets")
	streamFactory := newTCPStreamFactory(prof.opts.Port)
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	requestlog := make(map[string]HTTPLog)

	go func() {
		for {
			select {
			case v := <-streamFactory.logch:
				if v.url == "" {
					continue
				}

				if !prof.stats.DoFilter(v.url, v.method, v.time.String()) {
					continue
				}

				prof.mu.Lock()
				if v.isRequest {
					// request
					requestlog[v.id] = v
				} else {
					// response
					restime := v.time.Sub(requestlog[v.id].time)
					prof.stats.Set(requestlog[v.id].url, requestlog[v.id].method, v.status,
						float64(restime.Seconds()), float64(v.body), 0)
				}
				prof.mu.Unlock()
			}
		}
	}()

	packets := source.Packets()

profile:
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				break profile
			}
			tcp := packet.Layer(layers.LayerTypeTCP)
			if tcp != nil {
				tcp := tcp.(*layers.TCP)
				c := Context{
					CaptureInfo: packet.Metadata().CaptureInfo,
				}
				assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
			}
		case <-prof.sig:
			log.Println("Stopping to read packets")
			break profile
		}

	}

	assembler.FlushAll()
	streamFactory.WaitGoRoutines()
	prof.print()

	return nil
}

func formattedTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.999999999")
}

func headersToString(header http.Header) string {
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] > keys[j]
	})

	headers := make([]string, 0, len(keys))
	for _, k := range keys {
		headers = append(headers, fmt.Sprintf("%s: %s", k, strings.Join(header[k], ",")))
	}

	return strings.Join(headers, " ")
}

func requestLog(t time.Time, method, url string, body int, header http.Header) string {
	return fmt.Sprintf("-> %s %s %s %d bytes %s",
		formattedTime(t), method, url, body, headersToString(header),
	)
}

func responseLog(t time.Time, method, url string, body, status int, restime float64, header http.Header) string {
	return fmt.Sprintf("<- %s %s %s %d bytes %d %f sec %s",
		formattedTime(t), method, url, body,
		status, restime, headersToString(header),
	)
}

func (prof *HTTPProfiler) LiveLogging() error {
	handle, err := openLive(prof.opts.Iface, prof.opts.Int32Snaplen())
	if err != nil {
		return err
	}
	defer handle.Close()

	bpffilter := bpfFilterWithPort(prof.opts.Port)
	log.Println(fmt.Sprintf("Using BPF filter %q", bpffilter))
	if err = handle.SetBPFFilter(bpffilter); err != nil {
		return fmt.Errorf("BPF filter error:", err)
	}

	source := newPacketSource(handle, prof.opts.Lazy)

	log.Println("Starting to read packets")
	streamFactory := newTCPStreamFactory(prof.opts.Port)
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	requestlog := make(map[string]HTTPLog)

	go func() {
		for {
			select {
			case v := <-streamFactory.logch:
				if v.url == "" {
					continue
				}

				prof.mu.Lock()
				if v.isRequest {
					// request
					requestlog[v.id] = v
				} else {

					fmt.Println(
						requestLog(
							requestlog[v.id].time,
							requestlog[v.id].method,
							requestlog[v.id].url,
							requestlog[v.id].body,
							requestlog[v.id].header,
						),
					)

					restime := v.time.Sub(requestlog[v.id].time)
					fmt.Println(
						responseLog(
							v.time,
							v.method,
							v.url,
							v.body,
							v.status,
							float64(restime.Seconds()),
							v.header,
						),
					)
				}
				prof.mu.Unlock()
			}
		}
	}()

	packets := source.Packets()

live_logging:
	for {
		select {
		case packet := <-packets:

			tcp := packet.Layer(layers.LayerTypeTCP)
			if tcp != nil {
				tcp := tcp.(*layers.TCP)
				c := Context{
					CaptureInfo: packet.Metadata().CaptureInfo,
				}
				assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
			}
		case <-prof.sig:
			log.Println("Stopping to read packets")
			break live_logging
		}

	}

	assembler.FlushAll()
	streamFactory.WaitGoRoutines()

	return nil
}

func (prof *HTTPProfiler) print() {
	prof.stats.SortWithOptions()
	prof.stats.Print()
}
