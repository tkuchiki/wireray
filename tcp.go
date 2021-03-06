package wireray

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
)

type TCPStreamFactory struct {
	wg       sync.WaitGroup
	logch    chan HTTPLog
	port     int
	dumpBody bool
	gunzip   bool
}

func newTCPStreamFactory(port int, body, gunzip bool) *TCPStreamFactory {
	return &TCPStreamFactory{
		port:     port,
		logch:    make(chan HTTPLog),
		dumpBody: body,
		gunzip:   gunzip,
	}
}

func (factory *TCPStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	stream := &TCPStream{
		net:       net,
		transport: transport,
		reversed:  tcp.SrcPort == layers.TCPPort(factory.port),
		ident:     fmt.Sprintf("%s:%s", net, transport),
		logch:     factory.logch,
		id:        uuid.New().String(),
		dumpBody:  factory.dumpBody,
		gunzip:    factory.gunzip,
	}

	stream.client = HTTPReader{
		bytes:    make(chan []byte),
		ident:    fmt.Sprintf("%s %s", net, transport),
		parent:   stream,
		isClient: true,
	}
	stream.server = HTTPReader{
		bytes:  make(chan []byte),
		ident:  fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
		parent: stream,
	}
	factory.wg.Add(2)
	go stream.client.run(&factory.wg)
	go stream.server.run(&factory.wg)

	return stream
}

func (factory *TCPStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

type TCPStream struct {
	net, transport gopacket.Flow
	reversed       bool
	client         HTTPReader
	server         HTTPReader
	ident          string
	logch          chan HTTPLog
	id             string
	url            string
	method         string
	dumpBody       bool
	gunzip         bool
}

func (t *TCPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (t *TCPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	length, _ := sg.Lengths()

	if skip != 0 {
		return
	}
	data := sg.Fetch(length)

	if length > 0 {
		if dir == reassembly.TCPDirClientToServer && !t.reversed {
			t.client.bytes <- data
		} else {
			t.server.bytes <- data
		}
	}

}

func (t *TCPStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	close(t.client.bytes)
	close(t.server.bytes)

	return false
}

func openLive(iface string, snaplen int32) (*pcap.Handle, error) {
	return pcap.OpenLive(iface, snaplen, true, pcap.BlockForever)
}

func openOffline(pfile string) (*pcap.Handle, error) {
	return pcap.OpenOffline(pfile)
}

func newPacketSource(handle *pcap.Handle, lazy bool) *gopacket.PacketSource {
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = lazy
	source.NoCopy = true

	return source
}

func bpfFilterWithPort(port int) string {
	return fmt.Sprintf("tcp and port %d", port)
}
