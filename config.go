package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

var Metrics = map[string]snmpMetric{}

type indexType string

type index struct {
	LabelName string    `yaml:"labelname"`
	Type      indexType `yaml:"type"`
	Lookup    string    `yaml:"lookup"`
}

type snmpMetric struct {
	Name    string  `yaml:"name"`
	OID     string  `yaml:"oid"`
	Help    string  `yaml:"help"`
	Indexes []index `yaml:"indexes"`
}

type config struct {
	Metrics []snmpMetric `yaml:"metrics"`
	Hosts   []host       `yaml:"hosts"`
}

type host struct {
	Address   string   `yaml:"address"`
	Port      uint16   `yaml:"port"`
	Community string   `yaml:"community"`
	Version   string   `yaml:"version"`
	Metrics   []string `yaml:"host_metrics"`
	Walk      []string `yaml:"walk"`
}

func loadConfig(path string) (*config, error) {
	var c config
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, err
	}
	// build a list of metrics in the config
	for _, metric := range c.Metrics {
		Metrics[metric.OID] = metric
	}
	return &c, nil
}
