package main

import (
	"mptcp_sniffer/proto/github.com/protobuf/types/mptcp"
	"testing"
	"time"
)

func testCB(msg *mptcp.MPTCPMessage) {
	print("")
}

func TestBatch(t *testing.T) {

	bp := CreateBatchProcessor(5, testCB)
	bp.Insert(createTestMessage())

	time.Sleep(time.Duration(20 * 1000))
}

func createTestMessage() *mptcp.MPTCPMessage {
	options := make([]string, 1)
	options = append(options, "FOO")
	message := &mptcp.MPTCPMessage{}
	message.SrcAddr = "srcAdr"
	message.DstAddr = "dstAdr"
	message.SrcPort = uint32(11)
	message.DstPort = uint32(11)
	message.SeqNum = 1
	message.MptcpOptions = options
	return message
}
