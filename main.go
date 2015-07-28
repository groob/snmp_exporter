package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/soniah/gosnmp"
)

var (
	wg sync.WaitGroup

	collected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "snmp_collected_metrics",
		Help: "Number of Walked OIDs",
	})
)

func main() {
	path := "config.yml"
	config, err := loadConfig(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, host := range config.Hosts {
		c := newSNMPCollector(host)
		prometheus.MustRegister(c)
	}
	http.Handle("/metrics", prometheus.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}

type snmpCollector struct {
	host    host
	client  *gosnmp.GoSNMP
	ch      chan gosnmp.SnmpPDU
	pduList map[string]gosnmp.SnmpPDU
	// mu      *sync.Mutex
}

func newSNMPClient(h host) *gosnmp.GoSNMP {
	// TODO: Make version optional, port default to 161
	// and default community to 'public'
	return &gosnmp.GoSNMP{
		Target:    h.Address,
		Port:      h.Port,
		Community: h.Community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}
}

func newSNMPCollector(h host) *snmpCollector {
	c := &snmpCollector{
		host:    h,
		ch:      make(chan gosnmp.SnmpPDU, 0),
		pduList: make(map[string]gosnmp.SnmpPDU),
		// mu:      &sync.Mutex{},
	}
	c.walkHost()
	return c
}

func (c *snmpCollector) walkHost() {
	client := newSNMPClient(c.host)
	for _, oid := range c.host.Walk {
		c.walk(oid, client)
	}
}

func (c *snmpCollector) walk(oid string, client *gosnmp.GoSNMP) {
	err := client.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer client.Conn.Close()
	err = client.BulkWalk(oid, c.addPDU)
	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
}

func (c *snmpCollector) addPDU(pdu gosnmp.SnmpPDU) error {
	c.pduList[strings.TrimLeft(pdu.Name, ".")] = pdu
	return nil
}

// newDesc converts one data source of a value list to a Prometheus description.
func newDesc(c *snmpCollector, oid string) *prometheus.Desc {
	var name, help string
	for metricOID := range Metrics {
		if oid[:len(metricOID)] == metricOID {
			name = Metrics[metricOID].Name
			help = fmt.Sprintf(Metrics[metricOID].Help)
		}
	}
	return prometheus.NewDesc(name, help, []string{}, prometheus.Labels{})
}

func newMetric(c *snmpCollector, oid string) (prometheus.Metric, error) {
	var value float64
	var valueType prometheus.ValueType
	switch v := c.pduList[oid]; v.Type {
	case gosnmp.Counter32, gosnmp.Counter64:
		val := gosnmp.ToBigInt(v.Value)
		valueType = prometheus.CounterValue
		value = float64(val.Uint64())
	case gosnmp.Gauge32, gosnmp.Integer:
		val := gosnmp.ToBigInt(v.Value)
		valueType = prometheus.CounterValue
		value = float64(val.Uint64())
	default:
		fmt.Println(newDesc(c, oid))
		fmt.Println(v.Type)
	}
	return prometheus.NewConstMetric(newDesc(c, oid), valueType, value)
}

// Collect implements prometheus.Collector.
func (c *snmpCollector) Collect(ch chan<- prometheus.Metric) {
	for oid := range c.pduList {
		for metric := range Metrics {
			if oid[:len(metric)] == metric {
				m, err := newMetric(c, oid)
				if err != nil {
					log.Println(err)
					continue
				}
				ch <- m
			}
		}
	}
}

// Describe implements prometheus.Collector.
func (c snmpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collected.Desc()
}
