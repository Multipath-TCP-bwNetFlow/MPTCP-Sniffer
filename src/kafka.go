package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/Shopify/sarama"
	"github.com/golang/protobuf/proto"
	"log"
	"mptcp_sniffer/proto/github.com/protobuf/types/mptcp"
	"os"
	"strings"
	"sync"
	"time"
)

// simplified version of bwNetFlow kafka connector
// only producer is implemented
// no support for prometheus

type Connector struct {
	user        string
	pass        string
	authDisable bool
	tlsDisable  bool

	producer         sarama.AsyncProducer
	producerChannels map[string](chan *mptcp.MPTCPMessage)
	producerWg       *sync.WaitGroup
}

// DisableAuth disables authentification
func (connector *Connector) DisableAuth() {
	connector.authDisable = true
}

// DisableTLS disables ssl/tls connection
func (connector *Connector) DisableTLS() {
	connector.tlsDisable = true
}

// SetAuth explicitly set which login to use in SASL/PLAIN auth via TLS
func (connector *Connector) SetAuth(user string, pass string) {
	connector.user = user
	connector.pass = pass
}

// Set anonymous credentials as login method.
func (connector *Connector) SetAuthAnon() {
	connector.user = "anon"
	connector.pass = "anon"
}

// Check environment to infer which login to use in SASL/PLAIN auth via TLS
// Requires KAFKA_SASL_USER and KAFKA_SASL_PASS to be set for this process.
func (connector *Connector) SetAuthFromEnv() error {
	connector.user = os.Getenv("KAFKA_SASL_USER")
	connector.pass = os.Getenv("KAFKA_SASL_PASS")
	if connector.user == "" || connector.pass == "" {
		return errors.New("Setting Kafka SASL info from Environment was unsuccessful.")
	}
	return nil
}

func (connector *Connector) NewBaseConfig() *sarama.Config {
	config := sarama.NewConfig()

	// NOTE: This version enables Sarama support for everything we need and
	// more. However, a lower version might suffice to.
	// Actual, higher cluster versions are still supported with this.
	// Consider making this configurable anyways
	version, err := sarama.ParseKafkaVersion("2.4.0")
	if err != nil {
		log.Panicf("Error parsing Kafka version: %v", err)
	}
	config.Version = version

	if !connector.tlsDisable {
		// Enable TLS
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			log.Panicf("TLS Error: %v", err)
		}
		config.Net.TLS.Enable = true
		config.Net.TLS.Config = &tls.Config{RootCAs: rootCAs}
	}

	if !connector.authDisable {
		config.Net.SASL.Enable = true

		if connector.user == "" && connector.pass == "" {
			log.Println("No Auth information is set. Assuming anonymous auth...")
			connector.SetAuthAnon()
		}
		config.Net.SASL.User = connector.user
		config.Net.SASL.Password = connector.pass
	}

	return config
}

// Start a Kafka Producer with the specified parameters. The channel returned
// by ProducerChannel will be accepting your input.
func (connector *Connector) StartProducer(broker string) error {
	var err error
	brokers := strings.Split(broker, ",")
	config := connector.NewBaseConfig()

	config.Producer.RequiredAcks = sarama.WaitForLocal       // Only wait for the leader to ack
	config.Producer.Compression = sarama.CompressionSnappy   // Compress messages
	config.Producer.Flush.Frequency = 500 * time.Millisecond // Flush batches every 500ms
	config.Producer.Return.Successes = false                 // this would block until we've read the ACK, just don't
	config.Producer.Return.Errors = true                     // TODO: make configurable as logging feature

	connector.producerChannels = make(map[string](chan *mptcp.MPTCPMessage))
	connector.producerWg = &sync.WaitGroup{}
	// everything declared and configured, lets go
	connector.producer, err = sarama.NewAsyncProducer(brokers, config)
	if err != nil {
		log.Panicf("Kafka Producer: Error creating producer client: %v", err)
	}
	log.Println("Kafka Producer: Connection established.")
	return nil
}

// Return the channel used for handing over Flows to the Kafka Producer.
// If writing to this channel blocks, check the log.
func (connector *Connector) ProducerChannel(topic string) chan *mptcp.MPTCPMessage {
	if _, initialized := connector.producerChannels[topic]; !initialized {
		connector.producerChannels[topic] = make(chan *mptcp.MPTCPMessage)
		connector.producerWg.Add(1)
		go func() {
			for message := range connector.producerChannels[topic] {
				binary, err := proto.Marshal(message)
				if err != nil {
					log.Printf("Kafka Producer: Could not encode message to topic %s with error '%v'", topic, err)
					continue
				}
				connector.producer.Input() <- &sarama.ProducerMessage{
					Topic:     topic,
					Timestamp: time.Unix(message.TimestampCaptured, 0),
					Value:     sarama.ByteEncoder(binary),
				}
			}
			log.Printf("Kafka Producer: Terminating topic %s, channel has closed", topic)
			connector.producerWg.Done()
		}()

		go func() {
			for {
				select {
				case err := <-connector.producer.Errors():
					log.Println(err)
				}
			}
		}()
	}
	return connector.producerChannels[topic]
}
