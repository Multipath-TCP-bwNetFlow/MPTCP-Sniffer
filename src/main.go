package main

import (
	"flag"
	"io"
	"log"
	"mptcp_sniffer/proto/github.com/protobuf/types/mptcp"
	"os"
	"time"
)

var (
	kafkaBroker = flag.String("kafka.brokers", "127.0.0.1:9092,[::1]:9092", "Kafka brokers list separated by commas")

	kafkaUser        = flag.String("kafka.user", "", "Kafka username to authenticate with")
	kafkaPass        = flag.String("kafka.pass", "", "Kafka password to authenticate with")
	kafkaAuthAnon    = flag.Bool("kafka.auth_anon", true, "Set Kafka Auth Anon")
	kafkaDisableTLS  = flag.Bool("kafka.disable_tls", true, "Whether to use tls or not")
	kafkaDisableAuth = flag.Bool("kafka.disable_auth", true, "Whether to use auth or not")

	kafkaOutTopic = flag.String("kafka.out.topic", "mptcp-packets", "Kafka topic to produce to")

	networkInf = flag.String("inf", "en0", "network interface to sniff on")
	logFile    = flag.String("log", "./mptcp_sniffer.log", "Location of the log file.")
	logPackets = flag.Bool("logPackets", true, "Should packets be logged.")

	interval = flag.Uint("interval", 60, "Should packets be locked.")
)

var kafkaConnection Connector

func main() {
	logfile := prepareLogger()
	if logfile == nil {
		return
	}
	defer logfile.Close()

	log.Println("Write packets to: " + *kafkaOutTopic)

	batchProcessor := CreateBatchProcessor(*interval, cb)
	defer batchProcessor.Stop()
	initKafka()
	Sniff(*networkInf, batchProcessor.Insert) // blocks
}

func cb(msg *mptcp.MPTCPMessage) {
	if *logPackets {
		log.Println("-------------------------- New packet:")
		log.Println(msg)
	}
	kafkaConnection.ProducerChannel(*kafkaOutTopic) <- msg
}

func prepareLogger() *os.File {
	flag.Parse()
	var err error
	logfile, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		println("Error opening file for logging: %v", err)
		return nil
	}
	mw := io.MultiWriter(os.Stdout, logfile)
	log.SetOutput(mw)
	log.Println("-------------------------- Started.")
	return logfile
}

func initKafka() {
	var err error
	var kafkaConn = Connector{}

	if *kafkaDisableTLS {
		log.Println("kafkaDisableTLS ...")
		kafkaConn.DisableTLS()
	}
	if *kafkaDisableAuth {
		log.Println("kafkaDisableAuth ...")
		kafkaConn.DisableAuth()
	} else { // set Kafka auth
		if *kafkaAuthAnon {
			kafkaConn.SetAuthAnon()
		} else if *kafkaUser != "" {
			kafkaConn.SetAuth(*kafkaUser, *kafkaPass)
		} else {
			log.Println("No explicit credentials available, trying env.")
			err = kafkaConn.SetAuthFromEnv()
			if err != nil {
				log.Println("No credentials available, using 'anon:anon'.")
				kafkaConn.SetAuthAnon()
			}
		}
	}

	err = kafkaConn.StartProducer(*kafkaBroker)
	if err != nil {
		log.Println("StartProducer:", err)
		// sleep to make auto restart not too fast and spamming connection retries
		time.Sleep(5 * time.Second)
		return
	}
	kafkaConnection = kafkaConn
}
