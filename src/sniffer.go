package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"mptcp_sniffer/proto/github.com/protobuf/types/mptcp"
	"time"
)

type Send func(*mptcp.MPTCPMessage)

const MPTCPOptionKind = 30

// device e.g. eth0
func Sniff(device string, send Send) {
	fmt.Printf("Start sniffing on %s", device)

	if handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet, send)
		}
	}
}

func handlePacket(packet gopacket.Packet, send Send) {
	ethernetFrame := gopacket.NewPacket(packet.Data(), layers.LayerTypeEthernet, gopacket.Default)
	if tcpLayer := ethernetFrame.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		srcAddr, dstAddr := extractIpAddresses(ethernetFrame)
		tcp, _ := tcpLayer.(*layers.TCP)
		var options []string
		for _, opt := range tcp.Options {
			if opt.OptionType == MPTCPOptionKind {
				if decoded := decodeMPTCPOptions(opt); decoded != "" {
					options = append(options, decoded)
				}
			}
		}
		if options != nil && len(options) > 0 {
			message := createMessage(srcAddr, dstAddr, tcp.SrcPort, tcp.DstPort, tcp.Seq, options)
			send(message)
		}
	}
}

func extractIpAddresses(ethernetFrame gopacket.Packet) (string, string) {
	var srcAddr string
	var srcDst string

	if ipv4Layer := ethernetFrame.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcAddr = ipv4.SrcIP.String()
		srcDst = ipv4.DstIP.String()
	}
	if ipv6Layer := ethernetFrame.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		srcAddr = ipv6.SrcIP.String()
		srcDst = ipv6.DstIP.String()
	}
	return srcAddr, srcDst
}

func createMessage(srcAdr, dstAdr string, srcPort, dstPort layers.TCPPort, seqNum uint32, options []string) *mptcp.MPTCPMessage {
	message := &mptcp.MPTCPMessage{}
	message.SrcAddr = srcAdr
	message.DstAddr = dstAdr
	message.SrcPort = uint32(srcPort)
	message.DstPort = uint32(dstPort)
	message.SeqNum = seqNum
	message.TimestampCaptured = time.Now().Unix()
	message.MptcpOptions = options
	return message
}

// according to rfc6824
func decodeMPTCPOptions(option layers.TCPOption) string {
	firstByte := option.OptionData[0]
	masked := firstByte & 0xF0
	switch masked {
	case 0x00:
		return "MP_CAPABLE"
	case 0x10:
		return "MP_JOIN"
	case 0x20:
		return "DSS"
	case 0x30:
		return "ADD_ADDR"
	case 0x40:
		return "REMOVE_ADDR"
	case 0x50:
		return "MP_PRIO"
	case 0x60:
		return "MP_FAIL"
	case 0x70:
		return "MP_FASTCLOSE"
	default:
		return ""
	}
}
