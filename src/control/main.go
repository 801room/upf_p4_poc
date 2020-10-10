package main

import (
	"context"
	"flag"
	"time"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
	"github.com/antoninbas/p4runtime-go-client/pkg/util/conversion"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	defaultAddr     = "127.0.0.1:50051"
	defaultN4Addr   = "127.0.0.1:8805"
	defaultN3Addr   = "193.168.1.3"
	defaultDeviceID = 0
	UPLINK = 1
	DOWNLINK = 2
)

type Pdr struct {
	pdrId uint16
	fteid_teid uint32
	fteid_ip net.IP
	ueip net.IP
	farId uint32
	outer_header_remove uint8
	direction int32
}

type Far struct{
	farId uint32
	bFoward bool
	fwdParm *ie.OuterHeaderCreationFields
}

var g_farMap map[uint32]Far
var g_n3Ip net.IP

func handleStreamMessages(p4RtC *client.Client, messageCh <-chan *p4_v1.StreamMessageResponse) {
	for message := range messageCh {
		switch m := message.Update.(type) {
		case *p4_v1.StreamMessageResponse_Packet:
			log.Debugf("Received PacketIn")
		case *p4_v1.StreamMessageResponse_IdleTimeoutNotification:
			log.Debugf("Received IdleTimeoutNotification")
		case *p4_v1.StreamMessageResponse_Error:
			log.Errorf("Received StreamError")
		default:
			log.Errorf("Received unknown stream message %t",m)
		}
	}
}

func initialize(p4RtC *client.Client) error {
	/*step1: set unic l2 foward table */
	/*h1a mac:00:00:00:00:00:1A port 3*/
	h1a_mac := "00:00:00:00:00:1A"
	h1aMac_p4, _:= conversion.MacToBinary(h1a_mac)
	egressPort, _ := conversion.UInt32ToBinary(3, 2)
	dmacEntry := p4RtC.NewTableEntry("IngressPipeImpl.l2_exact_table", "IngressPipeImpl.set_egress_port",
		[]client.MatchInterface{&client.ExactMatch{h1aMac_p4}}, [][]byte{egressPort}, nil)
	if err := p4RtC.InsertTableEntry(dmacEntry); err != nil {
		return fmt.Errorf("Cannot insert default action for 'dmac': %v", err)
	}
	/*h1b mac:00:00:00:00:00:1B port 4*/
	h1b_mac := "00:00:00:00:00:1B"
	h1bMac_p4, _:= conversion.MacToBinary(h1b_mac)
	egressPort, _ = conversion.UInt32ToBinary(4, 2)
	dmacEntry = p4RtC.NewTableEntry("IngressPipeImpl.l2_exact_table", "IngressPipeImpl.set_egress_port",
		[]client.MatchInterface{&client.ExactMatch{h1bMac_p4}}, [][]byte{egressPort}, nil)
	if err := p4RtC.InsertTableEntry(dmacEntry); err != nil {
		return fmt.Errorf("Cannot insert default action for 'dmac': %v", err)
	}

	/*step2:set broadcast l2 foward for bypass arp */
	/*h1a arp request fwd to h1b(port:4)*/
	brdcastMac := "FF:FF:FF:FF:FF:FF"
	brdMac_p4,_ := conversion.MacToBinary(brdcastMac)
	egressPort, _ = conversion.UInt32ToBinary(4, 2)
	dmacEntry = p4RtC.NewTableEntry("IngressPipeImpl.l2_forward_bypass_table", "IngressPipeImpl.set_egress_port",
		[]client.MatchInterface{&client.ExactMatch{h1aMac_p4},&client.ExactMatch{brdMac_p4}}, [][]byte{egressPort}, nil)
	if err := p4RtC.InsertTableEntry(dmacEntry); err != nil {
		return fmt.Errorf("Cannot insert default action for 'dmac': %v", err)
	}

	/*h1b arp request fwd to h1a(port:3)*/
	egressPort, _ = conversion.UInt32ToBinary(3, 2)
	dmacEntry = p4RtC.NewTableEntry("IngressPipeImpl.l2_forward_bypass_table", "IngressPipeImpl.set_egress_port",
		[]client.MatchInterface{&client.ExactMatch{h1bMac_p4},&client.ExactMatch{brdMac_p4}}, [][]byte{egressPort}, nil)
	if err := p4RtC.InsertTableEntry(dmacEntry); err != nil {
		return fmt.Errorf("Cannot insert default action for 'dmac': %v", err)
	}
	return nil
}

func pfcp_tran_uplink(p4RtC *client.Client,pdr *Pdr) error{
	log.Debug("pdr id:",pdr.pdrId,"pdr fteid-ip:",pdr.fteid_ip," teid ",pdr.fteid_teid)
	dst_addr_p4, err:= conversion.IpToBinary(pdr.fteid_ip.String())
	if err != nil{
		log.Info("conversion dst_addr_p4 error:",err)
	}
	teid_p4, err:= conversion.UInt32ToBinary(pdr.fteid_teid, 0)
	if err != nil{
		log.Info("conversion teid_p4 error:",err)
	}

	pdrId_p4, err:= conversion.UInt32ToBinary(uint32(pdr.pdrId),2)
	if err != nil{
		log.Info("conversion pdrId_p4 error:",err)
	}
	teidEntry := p4RtC.NewTableEntry("IngressPipeImpl.upf_f_teid_ueip_filter_table", "IngressPipeImpl.set_pdr_id",
		[]client.MatchInterface{&client.ExactMatch{dst_addr_p4},
			&client.ExactMatch{teid_p4}}, [][]byte{pdrId_p4}, nil)
	teidEntry.Priority = 1
	if err := p4RtC.InsertTableEntry(teidEntry); err != nil {
		return fmt.Errorf("Cannot insert 'teidEntry': %v", err)
	}
	log.Info("pfcp_tran_uplink teidEntry ok!")

	if 0==pdr.outer_header_remove {
		pdr_hdrm_entry := p4RtC.NewTableEntry("IngressPipeImpl.upf_pdr_header_rm_table", "IngressPipeImpl.gtpu_decap",
			[]client.MatchInterface{&client.ExactMatch{pdrId_p4}}, nil, nil)
		if err := p4RtC.InsertTableEntry(pdr_hdrm_entry); err != nil {
			return fmt.Errorf("Cannot insert 'pdr_hdrm_entry': %v", err)
		}
	}
	log.Info("pfcp_tran_uplink pdr_hdrm_entry ok!!")

	farId_p4, err:= conversion.UInt32ToBinary(pdr.farId,0)
	if err != nil{
		log.Info("conversion pdrId_p4 error:",err)
	}

	pdr_getfar_entry := p4RtC.NewTableEntry("IngressPipeImpl.upf_pdr_getfar_table", "IngressPipeImpl.set_far_id",
		[]client.MatchInterface{&client.ExactMatch{pdrId_p4}}, [][]byte{farId_p4}, nil)
	if err := p4RtC.InsertTableEntry(pdr_getfar_entry); err != nil {
		return fmt.Errorf("Cannot insert 'pdr_getfar_entry': %v", err)
	}
	log.Info("pfcp_tran_uplink pdr_getfar_entry ok!!!")
	far, ok:= g_farMap[pdr.farId]
	if ok && far.bFoward {
		if far.fwdParm == nil {
			far_action_entry := p4RtC.NewTableEntry("IngressPipeImpl.upf_far_action_table", "IngressPipeImpl.nop",
				[]client.MatchInterface{&client.ExactMatch{farId_p4}}, nil, nil)
			if err := p4RtC.InsertTableEntry(far_action_entry); err != nil {
				return fmt.Errorf("Cannot insert 'far_action_entry': %v", err)
			}
			log.Info("pfcp_tran_uplink far_action_entry ok!!!!")
		}
	}
	return nil
}

func pfcp_tran_downlink(p4RtC *client.Client,pdr *Pdr) error {
	log.Debug("pdr id:",pdr.pdrId,"pdr ueip:",pdr.ueip)

	pdrId_p4, err:= conversion.UInt32ToBinary(uint32(pdr.pdrId),2)
	if err != nil{
		log.Info("conversion pdrId_p4 error:",err)
	}
	dst_addr_p4, err:= conversion.IpToBinary(pdr.ueip.String())
	if err != nil{
		log.Info("conversion dst_addr_p4 error:",err)
	}

	ueEntry := p4RtC.NewTableEntry("IngressPipeImpl.upf_ue_filter_table", "IngressPipeImpl.set_pdr_id",
		[]client.MatchInterface{&client.ExactMatch{dst_addr_p4}}, [][]byte{pdrId_p4}, nil)
	if err := p4RtC.InsertTableEntry(ueEntry); err != nil {
		return fmt.Errorf("Cannot insert 'ueEntry': %v", err)
	}
	log.Info("pfcp_tran_downlink ueEntry ok!")

	farId_p4, err:= conversion.UInt32ToBinary(pdr.farId,0)
	if err != nil{
		log.Info("conversion pdrId_p4 error:",err)
	}
	pdr_getfar_entry := p4RtC.NewTableEntry("IngressPipeImpl.upf_pdr_getfar_table", "IngressPipeImpl.set_far_id",
		[]client.MatchInterface{&client.ExactMatch{pdrId_p4}}, [][]byte{farId_p4}, nil)
	if err := p4RtC.InsertTableEntry(pdr_getfar_entry); err != nil {
		return fmt.Errorf("Cannot insert 'pdr_getfar_entry': %v", err)
	}
	log.Info("pfcp_tran_downlink pdr_getfar_entry ok!!")

	/*far table*/
	far, ok := g_farMap[pdr.farId]
	log.Debug("farid:", pdr.farId,"map find:",ok,"bFoward:",far.bFoward,"fwdParam:",far.fwdParm)
	if ok && far.bFoward && far.fwdParm != nil{
		teid_p4, _:= conversion.UInt32ToBinary(far.fwdParm.TEID,0)
		n3ip_p4, _:= conversion.IpToBinary(g_n3Ip.String())
		gnbIp_p4, _:= conversion.IpToBinary(far.fwdParm.IPv4Address.String())
		far_action_entry := p4RtC.NewTableEntry("IngressPipeImpl.upf_far_action_table", "IngressPipeImpl.gtpu_encap",
			[]client.MatchInterface{&client.ExactMatch{farId_p4}}, [][]byte{teid_p4,n3ip_p4,gnbIp_p4}, nil)
		if err := p4RtC.InsertTableEntry(far_action_entry); err != nil {
			return fmt.Errorf("Cannot insert 'far_action_entry': %v", err)
		}
		log.Info("pfcp_tran_downlink far_action_entry ok!!!")
	}
	return nil
}
func pfcp_rule_tran_p4table(p4RtC *client.Client,pdr *Pdr) error{
	if pdr.direction == UPLINK{
		return pfcp_tran_uplink(p4RtC,pdr)
	}else{
		return pfcp_tran_downlink(p4RtC,pdr)
	}
}


func pfcp_HeartBeat_handle(msg message.Message,addr net.Addr){
	hbreq, ok := msg.(*message.HeartbeatRequest)
	if !ok {
		log.Info("got unexpected message: %s, from: %s", msg.MessageTypeName(),addr)
	}

	ts, err := hbreq.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		log.Info("got Heartbeat Request with invalid TS: %s, from: %s", err, addr)
	} else {
		log.Info("got Heartbeat Request with TS:", ts," from:" ,addr)
	}
}

func pfcp_SessionEstablish_handle(msg message.Message,addr net.Addr,p4RtC *client.Client){
	if g_farMap == nil{
		g_farMap = make(map[uint32]Far, 10)
	}
	pdrs := make([]Pdr, 0)
	req, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		log.Info("got unexpected message: %s, from: %s", msg.MessageTypeName(),addr)
	}
	/**session decode
	* f-seid
	*/
	g_n3Ip = net.ParseIP(defaultN3Addr)

	fseid,err := req.CPFSEID.FSEID()
	if err != nil{
		log.Info("SessionEstablish Request with invalid fseid err:",err," from:", addr)
	} else{
		log.Info("cp fseid-seid:", fseid.SEID, " addr:",fseid.IPv4Address)
	}

	/*pdr decode
	* pdrId,pdi->sourceInterface,pdi->f-teid,pdi->ueip
	*/
	for _,crtPdrItem := range req.CreatePDR{
		var pdr Pdr
		pdrId,err:=crtPdrItem.PDRID()
		if err != nil{
			log.Info("SessionEstablish Request with invalid pdrId err:",err," from:", addr)
		} else{
			log.Info("pdrId:", pdrId, " addr:",addr)
			pdr.pdrId = pdrId
		}

		farId,err:=crtPdrItem.FARID()
		if err == nil{
			pdr.farId = farId
		}

		sourceInt,err := crtPdrItem.SourceInterface()
		if err == nil{
			log.Info("pdi source interface:", sourceInt)
		}
		//"Access" interface value is 0
		if 0 == sourceInt{
			pdr.direction = UPLINK
		}else{
			pdr.direction = DOWNLINK
		}

		/*go-pfcp FTEID() has a bug ,need enumerate to find PDI*/
		crtIEs,_  := crtPdrItem.CreatePDR()
		if crtIEs != nil{
			for _,item := range crtIEs{
				if item.Type == ie.PDI{
					pdiIEs ,_ := item.PDI()
					for _,pdiIe := range pdiIEs{
						if pdiIe.Type == ie.FTEID{
							fteid, _ := pdiIe.FTEID()
							if fteid != nil{
								log.Info("fteid teid:",fteid.TEID," fteid addr:",fteid.IPv4Address)
								pdr.fteid_teid = fteid.TEID
								pdr.fteid_ip = fteid.IPv4Address
								g_n3Ip = pdr.fteid_ip
							}
						}
					}
				}
			}
		}

		ueip,err := crtPdrItem.UEIPAddress()
		if err == nil{
			log.Info("ueip:",ueip.IPv4Address)
			pdr.ueip = ueip.IPv4Address
		}

		outerRm,err:=crtPdrItem.OuterHeaderRemovalDescription()
		if err == nil{
			log.Info("outerRm:",outerRm)
			pdr.outer_header_remove = outerRm
		}else{
			pdr.outer_header_remove = 255
		}
		pdrs = append(pdrs, pdr)
	}
	/*far decode*/
	for _,crtFarItem := range req.CreateFAR{
		var far Far
		farId,err := crtFarItem.FARID()
		if err == nil{
			far.farId = farId
		}else{
			log.Error("CreateFAR decode farid error ",err)
		}
		bForw := crtFarItem.HasFORW()
		if err == nil{
			far.bFoward = bForw
		}
		frIEs,err := crtFarItem.ForwardingParameters()
		for _,frIe := range frIEs{
			if frIe.Type == ie.OuterHeaderCreation{
				outerHeaderField,_:= frIe.OuterHeaderCreation()
				if outerHeaderField != nil{
					far.fwdParm = outerHeaderField
					log.Info("far.fwdParm.TEID",outerHeaderField.TEID)
					log.Info("outerHeaderField",outerHeaderField)
				}
			}
		}
		log.Debug("g_farMap[far.farId]:",far.farId)
		g_farMap[far.farId] = far
	}

	log.Debug("pdrs length:",len(pdrs))
	for _, pdr_item:=range pdrs{
		err = pfcp_rule_tran_p4table(p4RtC,&pdr_item)
		if err != nil{
			log.Error("pfcp_rule_tran_p4table error:",err)
		}
	}
}

func n4Server(listen *string,p4RtC *client.Client){
	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("Cannot resolve n4 addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("Cannot start n4 socket: %v",err)
	}

	buf := make([]byte, 1500)
	for{
		log.Info("input")
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("message len:%d",n)
		msg, err := message.Parse(buf[:n])
		if err != nil {
			log.Info("ignored undecodable message: %x, error: %s msg:%s", buf[:n], err,msg)
			continue
		}
		switch(msg.MessageTypeName()){
			case "Heartbeat Request":
				log.Info("message.HeartbeatRequest")
				pfcp_HeartBeat_handle(msg,addr)
			case "Session Establishment Request":
				log.Info("message.SessionEstablishmentRequest")
				pfcp_SessionEstablish_handle(msg,addr,p4RtC)
			default:
				log.Info("unknow pfcp message")
		}
	}
}
func main() {
	var addr string
	flag.StringVar(&addr, "addr", defaultAddr, "P4Runtime server socket")
	var deviceID uint64
	flag.Uint64Var(&deviceID, "device-id", defaultDeviceID, "Device id")
	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose mode with debug log messages")
	var binPath string
	flag.StringVar(&binPath, "bin", "", "Path to P4 bin (not needed for bmv2 simple_switch_grpc)")
	var p4infoPath string
	flag.StringVar(&p4infoPath, "p4info", "", "Path to P4Info (not needed for bmv2 simple_switch_grpc)")
	var n4Addr string
	flag.StringVar(&n4Addr,"n4addr",defaultN4Addr,"N4 server socket")
	flag.Parse()

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	if binPath == "" || p4infoPath == "" {
		log.Fatalf("Missing .bin or P4Info")
	}

	log.Infof("Connecting to server at %s", addr)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Cannot connect to server: %v", err)
	}
	defer conn.Close()

	c := p4_v1.NewP4RuntimeClient(conn)
	/*
	resp, err := c.Capabilities(context.Background(), &p4_v1.CapabilitiesRequest{})
	if err != nil {
		log.Fatalf("Error in Capabilities RPC: %v", err)
	}
	log.Infof("P4Runtime server version is %s", resp.P4RuntimeApiVersion)
    */
	stopCh := signals.RegisterSignalHandlers()

	electionID := p4_v1.Uint128{High: 0, Low: 2}

	p4RtC := client.NewClient(c, deviceID, electionID)
	mastershipCh := make(chan bool)
	messageCh := make(chan *p4_v1.StreamMessageResponse, 1000)
	defer close(messageCh)
	go p4RtC.Run(stopCh, mastershipCh, messageCh)

	waitCh := make(chan struct{})

	go func() {
		sent := false
		for isMaster := range mastershipCh {
			if isMaster {
				log.Infof("We are master!")
				if !sent {
					waitCh <- struct{}{}
					sent = true
				}
			} else {
				log.Infof("We are not master!")
			}
		}
	}()

	// it would also be safe to spawn multiple goroutines to handle messages from the channel
	go handleStreamMessages(p4RtC, messageCh)

	timeout := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case <-ctx.Done():
		log.Fatalf("Could not acquire mastership within %v", timeout)
	case <-waitCh:
	}

	log.Info("Setting forwarding pipe")
	if err := p4RtC.SetFwdPipe(binPath, p4infoPath); err != nil {
		log.Fatalf("Error when setting forwarding pipe: %v", err)
	}

	if err := initialize(p4RtC); err != nil {
		log.Fatalf("Error when initializing defaults: %v", err)
	}

	/*N4 server start*/
	go n4Server(&n4Addr,p4RtC)

	log.Info("Do Ctrl-C to quit")
	<-stopCh
	log.Info("Stopping client")
}

