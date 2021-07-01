package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	namespace = "starwind"
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

var (
	labelNames = []string{""}
)

func newMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", metricName),
			docString,
			labelNames,
			constLabels,
		),
		Type: t,
	}
}

type metrics map[int]metricInfo

var (
	allMetrics   = metrics{}
	starwindInfo = prometheus.NewDesc(prometheus.BuildFQName(namespace, "version", "info"), "Starwind version info.", []string{"release_date", "version"}, nil)
	starwindUp   = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last scrape of Starwind successful.", nil, nil)
)

type Exporter struct {
	URI          string
	mutex        sync.RWMutex
	fetchStat    func() (*Devices, error)
	up           prometheus.Gauge
	totalScrapes prometheus.Counter
	allMetrics   map[int]metricInfo
	logger       log.Logger
}

type Config struct {
	Username string
	Password string
	Host     string
}

func (c *Config) NewExporter(uri string, timeout time.Duration, logger log.Logger) (*Exporter, error) {
	var fetchStat func() (*Devices, error)
	fetchStat, _ = fetchTCP(uri, timeout, c)

	return &Exporter{
		URI:       uri,
		fetchStat: fetchStat,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Was the last scrape of Starwind successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total Starwind scrapes.",
		}),
		logger: logger,
	}, nil

}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range allMetrics {
		ch <- m.Desc
	}

	ch <- starwindInfo
	ch <- starwindUp
	ch <- e.totalScrapes.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(starwindUp, prometheus.GaugeValue, up)
	ch <- e.totalScrapes
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()
	var err error

	devices, err := e.fetchStat()
	if err != nil {
		level.Error(e.logger).Log("msg", "Can't scrape starwind", "err", err)
		return 0
	}
	for _, device := range *devices {
		// do some things
		fmt.Println(device)
	}
	return 1

}

func fetchTCP(uri string, timeout time.Duration, config *Config) (func() (*Devices, error), error) {
	return func() (*Devices, error) {
		conn, err := dialTCP(uri, timeout)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(conn)

		// Send protocolversion 100
		if _, err := fmt.Fprintf(conn, "%s\n", "protocolversion 100"); err != nil {
			return nil, err
		}
		if err := checkSuccess(scanner); err != nil {
			return nil, err
		}

		// Login
		if _, err := fmt.Fprintf(conn, "%s %s %s\n", "login", config.Username, config.Password); err != nil {
			return nil, err
		}
		if err := checkSuccess(scanner); err != nil {
			return nil, err
		}

		// Get all metrics
		if _, err := fmt.Fprintf(conn, "%s\n", "list"); err != nil {
			return nil, err
		}
		if err := checkSuccess(scanner); err != nil {
			return nil, err
		}

		var id int
		var device Device
		var devices Devices
		var seen bool
		for scanner.Scan() {
			parsed := strings.Split(string(scanner.Bytes()), "=")
			fmt.Println(parsed)
			if parsed[0] == "DeviceName" {
				// We have a new device so append current device to devices
				if seen {
					d := device
					devices = append(devices, &d)
					// increment id
					id += 1
				}
				// set device to new device with new id
				device = Device{Id: id, Stats: make(map[string][]string)}
			} else if !seen {
				// skip loop as this is just preamble
				continue
			}

			if parsed[0] == "" && seen {
				// we are done so break
				d := device
				devices = append(devices, &d)
				break
			}

			device.Stats[parsed[0]] = append(device.Stats[parsed[0]], strings.Trim(parsed[1], "\""))
			// mark seen as true as we have just started processing stats
			seen = true
		}

		return &devices, nil
	}, nil
}

type Device struct {
	Id    int
	Stats map[string][]string
}

type Devices []*Device

func checkSuccess(scanner *bufio.Scanner) error {
	success_regex := regexp.MustCompile("200 Completed")
	timer := time.NewTimer(2 * time.Second)
	for scanner.Scan() {
		fmt.Println(string(scanner.Bytes()))
		match := success_regex.FindSubmatch(scanner.Bytes())
		if match != nil {
			return nil
		}
		select {
		case <-timer.C:
			break
		default:
		}
	}
	return fmt.Errorf("Error confirming success")
}

func dialTCP(uri string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(uri)
	if err != nil {
		return nil, err
	}

	ip, err := lookup(targetAddress)
	if err != nil {
		return nil, err
	}

	if ip.IP.To4() == nil {
		return nil, fmt.Errorf("Error resolving IP to ipv4")
	}

	dialTarget := net.JoinHostPort(ip.String(), port)
	dialer.Deadline = time.Now().Add(timeout)

	conn, err := dialer.Dial("tcp", dialTarget)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func lookup(uri string) (*net.IPAddr, error) {
	var c net.IP
	c = net.ParseIP(uri)
	if c != nil {
		return &net.IPAddr{IP: c}, nil
	}

	ips, err := net.LookupHost(uri)
	if err != nil {
		return nil, err
	}

	c = net.ParseIP(ips[0])
	if c == nil {
		return nil, fmt.Errorf("Invalid Domain")
	}
	ip := &net.IPAddr{IP: c}
	return ip, nil
}

func main() {
	var (
		webConfig         = webflag.AddFlags(kingpin.CommandLine)
		listenAddress     = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9101").String()
		metricsPath       = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		starwindScrapeURI = kingpin.Flag("starwind.scrape-uri", "URI on which to scrape Starwind.").Default("127.0.0.1:3261").String()
		starwindTimeout   = kingpin.Flag("starwind.timeout", "Timeout for trying to get stats from Starwind.").Default("5s").Duration()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("starwind_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting starwind_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	c := Config{
		Username: "root",
		Password: "starwind",
	}
	exporter, err := c.NewExporter(*starwindScrapeURI, *starwindTimeout, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating an exporter", "err", err)
		os.Exit(1)
	}
	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("starwind_exporter"))

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Starwind Exporter</title></head>
             <body>
             <h1>Starwind Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
