package options

import (
	"io"
	"io/ioutil"

	stats_options "github.com/tkuchiki/alp/options"

	"gopkg.in/yaml.v2"
)

type Options struct {
	StatsOptions *stats_options.Options `yaml:"stats_options"`
	Snaplen      int                    `yaml:snaplen`
	Iface        string                 `yaml:iface`
	Port         int                    `yaml:port`
	Pcap         string                 `yaml:pcap`
	Lazy         bool                   `yaml:lazy`
	Body         bool                   `yaml:body`
	Gunzip       bool                   `yaml:gunzip`
}

type Option func(*Options)

func Snaplen(i int) Option {
	return func(opts *Options) {
		if i > 0 {
			opts.Snaplen = i
		}
	}
}

func Iface(s string) Option {
	return func(opts *Options) {
		if s != "" {
			opts.Iface = s
		}
	}
}

func Port(i int) Option {
	return func(opts *Options) {
		if i > 0 {
			opts.Port = i
		}
	}
}

func Pcap(s string) Option {
	return func(opts *Options) {
		if s != "" {
			opts.Pcap = s
		}
	}
}

func Lazy(b bool) Option {
	return func(opts *Options) {
		if b {
			opts.Lazy = b
		}
	}
}

func Body(b bool) Option {
	return func(opts *Options) {
		if b {
			opts.Body = b
		}
	}
}

func Gunzip(b bool) Option {
	return func(opts *Options) {
		if b {
			opts.Gunzip = b
		}
	}
}

func NewOptions(opt ...Option) *Options {
	options := &Options{
		Snaplen: 65536,
	}

	for _, o := range opt {
		o(options)
	}

	statsOptions := stats_options.NewOptions()
	options.StatsOptions = statsOptions

	return options
}

func SetOptions(options *Options, opt ...Option) *Options {
	for _, o := range opt {
		o(options)
	}

	return options
}

func LoadOptionsFromReader(r io.Reader) (*Options, error) {
	opts := NewOptions()
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return opts, err
	}

	err = yaml.Unmarshal(buf, opts)

	return opts, err
}

func (o *Options) Int32Snaplen() int32 {
	return int32(o.Snaplen)
}

func (o *Options) Uint32Snaplen() uint32 {
	return uint32(o.Snaplen)
}
