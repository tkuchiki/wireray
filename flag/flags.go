package flag

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

type Flags struct {
	Common  *Common
	Profile *Profile
	Stats   *Stats
}

type Common struct {
	Snaplen int
	Iface   string
	Port    int
	Pcap    string
	Lazy    bool
}

type Profile struct {
	IsProfiling bool
	IsLogging   bool
}

type Stats struct {
	Config            string
	File              string
	Dump              string
	Load              string
	Max               bool
	Min               bool
	Avg               bool
	Sum               bool
	Cnt               bool
	SortUri           bool
	Method            bool
	MaxBody           bool
	MinBody           bool
	AvgBody           bool
	SumBody           bool
	P1                bool
	P50               bool
	P99               bool
	Stddev            bool
	Reverse           bool
	QueryString       bool
	Tsv               bool
	NoHeaders         bool
	ApptimeLabel      string
	ReqtimeLabel      string
	StatusLabel       string
	SizeLabel         string
	MethodLabel       string
	UriLabel          string
	TimeLabel         string
	Limit             int
	Location          string
	Includes          string
	Excludes          string
	IncludeStatuses   string
	ExcludeStatuses   string
	Aggregates        string
	StartTime         string
	EndTime           string
	StartTimeDuration string
	EndTimeDuration   string
}

func NewFlags() *Flags {
	return &Flags{
		Common:  &Common{},
		Profile: &Profile{},
		Stats:   &Stats{},
	}
}

func (f *Flags) InitCommonFlags(app *kingpin.Application) {
	app.Flag("snaplen", "Snap length (number of bytes max to read per packet").Default("65536").IntVar(&f.Common.Snaplen)
	app.Flag("iface", "Interface to read packets from").Default("lo0").StringVar(&f.Common.Iface)
	app.Flag("port", "Port").Required().IntVar(&f.Common.Port)
	app.Flag("pcap", "Pcap file").StringVar(&f.Common.Pcap)
	app.Flag("lazy", "If true, do lazy decoding").BoolVar(&f.Common.Lazy)
}

func (f *Flags) InitProfileFlags(app *kingpin.CmdClause) {
	app.Flag("profiling", "If true, do profiling").BoolVar(&f.Profile.IsProfiling)
	app.Flag("logging", "If true, do logging").BoolVar(&f.Profile.IsLogging)

	app.Flag("config", "config file").Short('c').StringVar(&f.Stats.Config)
	app.Flag("file", "access log file").Short('f').StringVar(&f.Stats.File)
	app.Flag("dump", "dump profile data").Short('d').StringVar(&f.Stats.Dump)
	app.Flag("load", "load profile data").Short('l').StringVar(&f.Stats.Load)
	app.Flag("max", "sort by max response time").BoolVar(&f.Stats.Max)
	app.Flag("min", "sort by min response time").BoolVar(&f.Stats.Min)
	app.Flag("avg", "sort by avg response time").BoolVar(&f.Stats.Avg)
	app.Flag("sum", "sort by sum response time").BoolVar(&f.Stats.Sum)
	app.Flag("cnt", "sort by count").BoolVar(&f.Stats.Cnt)
	app.Flag("uri", "sort by uri").BoolVar(&f.Stats.SortUri)
	app.Flag("method", "sort by method").BoolVar(&f.Stats.Method)
	app.Flag("max-body", "sort by max body size").BoolVar(&f.Stats.MaxBody)
	app.Flag("min-body", "sort by min body size").BoolVar(&f.Stats.MinBody)
	app.Flag("avg-body", "sort by avg body size").BoolVar(&f.Stats.AvgBody)
	app.Flag("sum-body", "sort by sum body size").BoolVar(&f.Stats.SumBody)
	app.Flag("p1", "sort by 1 percentail response time").BoolVar(&f.Stats.P1)
	app.Flag("p50", "sort by 50 percentail response time").BoolVar(&f.Stats.P50)
	app.Flag("p99", "sort by 99 percentail response time").BoolVar(&f.Stats.P99)
	app.Flag("stddev", "sort by standard deviation response time").BoolVar(&f.Stats.Stddev)
	app.Flag("reverse", "reverse the result of comparisons").Short('r').BoolVar(&f.Stats.Reverse)
	app.Flag("query-string", "include query string").Short('q').BoolVar(&f.Stats.QueryString)
	app.Flag("tsv", "tsv format (default: table)").BoolVar(&f.Stats.Tsv)
	app.Flag("apptime-label", "apptime label").Default("apptime").StringVar(&f.Stats.ApptimeLabel)
	app.Flag("reqtime-label", "reqtime label").Default("reqtime").StringVar(&f.Stats.ReqtimeLabel)
	app.Flag("status-label", "status label").Default("status").StringVar(&f.Stats.StatusLabel)
	app.Flag("size-label", "size label").Default("size").StringVar(&f.Stats.SizeLabel)
	app.Flag("method-label", "method label").Default("method").StringVar(&f.Stats.MethodLabel)
	app.Flag("uri-label", "uri label").Default("uri").StringVar(&f.Stats.UriLabel)
	app.Flag("time-label", "time label").Default("time").StringVar(&f.Stats.TimeLabel)
	app.Flag("limit", "set an upper limit of the target uri").Default(fmt.Sprint(5000)).IntVar(&f.Stats.Limit)
	app.Flag("location", "location name").StringVar(&f.Stats.Location)
	app.Flag("includes", "don't exclude uri matching PATTERN (comma separated)").PlaceHolder("PATTERN,...").StringVar(&f.Stats.Includes)
	app.Flag("excludes", "exclude uri matching PATTERN (comma separated)").PlaceHolder("PATTERN,...").StringVar(&f.Stats.Excludes)
	app.Flag("include-statuses", "don't exclude status code matching PATTERN (comma separated)").PlaceHolder("PATTERN,...").StringVar(&f.Stats.IncludeStatuses)
	app.Flag("exclude-statuses", "exclude uri status code PATTERN (comma separated)").PlaceHolder("PATTERN,...").StringVar(&f.Stats.ExcludeStatuses)
	app.Flag("noheaders", "print no header line at all (only --tsv)").BoolVar(&f.Stats.NoHeaders)
	app.Flag("aggregates", "aggregate uri matching PATTERN (comma separated)").PlaceHolder("PATTERN,...").StringVar(&f.Stats.Aggregates)
	app.Flag("start-time", "since the start time").PlaceHolder("TIME").StringVar(&f.Stats.StartTime)
	app.Flag("end-time", "end time earlier").PlaceHolder("TIME").StringVar(&f.Stats.EndTime)
	app.Flag("start-time-duration", "since the start time (now - time.Duration)").PlaceHolder("TIME_DURATION").StringVar(&f.Stats.StartTimeDuration)
	app.Flag("end-time-duration", "end time earlier (now - time.Duration)").PlaceHolder("TIME_DURATION").StringVar(&f.Stats.EndTimeDuration)
}
