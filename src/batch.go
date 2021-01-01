package main

import (
	"mptcp_sniffer/proto/github.com/protobuf/types/mptcp"
	"strconv"
	"sync/atomic"
	"time"
)


/*
This is a simple stupid implementation.
Very likely that it will not deliver required performance. ¯\_(ツ)_/¯
*/

type Process func(*mptcp.MPTCPMessage)

type BatchProcessor struct {
	stack1 [] *mptcp.MPTCPMessage
	stack2 [] *mptcp.MPTCPMessage

	currentStack int32
	ticker *time.Ticker
}

func CreateBatchProcessor(bufferTime uint, processCB Process) *BatchProcessor {
	duration := time.Duration(bufferTime)
	ticker := time.NewTicker(duration * time.Second)
	bp := &BatchProcessor{
		make([]*mptcp.MPTCPMessage, 0),
		make([]*mptcp.MPTCPMessage, 0),
		1, ticker}

	go func() {
		for range  ticker.C {
			flush(processCB, bp)
		}
	}()
	return bp
}

func (bp * BatchProcessor)Insert(msg *mptcp.MPTCPMessage) {
	_currentStack := atomic.LoadInt32(&bp.currentStack)
	if _currentStack == 1 {
		bp.stack1 = append(bp.stack1, msg)
	} else {
		bp.stack2 = append(bp.stack2, msg)
	}
}

func (bp * BatchProcessor)Stop() {
	bp.ticker.Stop()
}

func flush(processCB Process, bp * BatchProcessor) {
	_currentStack := atomic.LoadInt32(&bp.currentStack)
	if _currentStack == 1 {
		atomic.StoreInt32(&bp.currentStack, 2)
		time.Sleep(100) // await edge case if item is currently appended to stack
		bp.stack1 = processStack(bp.stack1, processCB)
	} else {
		atomic.StoreInt32(&bp.currentStack, 1)
		time.Sleep(100) // await edge case if item is currently appended to stack
		bp.stack2 = processStack(bp.stack2, processCB)
	}
}

func processStack(stack []*mptcp.MPTCPMessage, processCB Process) []*mptcp.MPTCPMessage {
	flows := make([]*mptcp.MPTCPMessage, 0)
	for len(stack) > 0 {
		topIdx := len(stack) - 1
		packet := stack[topIdx]
		found := false
		for _, flow := range flows {
			if compareMPTCPMessages(packet, flow) {
				addOptionIfNotPresent(flow, packet)
				found = true
				break
			}
		}
		if !found {
			flows = append(flows, packet)
		}
		stack = stack[:topIdx]
	}

	for _, flow := range flows {
		processCB(flow)
	}
	return stack
}

func compareMPTCPMessages(f1, f2 *mptcp.MPTCPMessage) bool{
	f1Key := f1.SrcAddr + f1.DstAddr + strconv.Itoa(int(f1.SrcPort)) + strconv.Itoa(int(f1.DstPort))
	f2Key := f2.SrcAddr + f2.DstAddr + strconv.Itoa(int(f2.SrcPort)) + strconv.Itoa(int(f2.DstPort))
	return f1Key == f2Key
}

func addOptionIfNotPresent(flow, newItem *mptcp.MPTCPMessage) {
	for _ , newOption := range newItem.MptcpOptions {
		contained := false
		for _, containingOption := range flow.MptcpOptions {
				if containingOption == newOption {
					contained = true
				}
		}

		if !contained {
			flow.MptcpOptions = append(flow.MptcpOptions, newOption)
		}
	}
}