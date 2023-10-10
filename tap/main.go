package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"github.com/urfave/cli"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "n",
		},
		cli.StringFlag{
			Name: "ip",
		},
		cli.StringFlag{
			Name: "fake_mac",
		},
		cli.StringFlag{
			Name: "fake_ip",
		},
	}

	app.Action = func(c *cli.Context) error {
		ifaceName := c.String("n")
		ifaceIP := c.String("ip")
		fakeMAC := c.String("fake_mac")
		fakeIP := c.String("fake_ip")

		return startTAP(ifaceName, ifaceIP, fakeMAC, fakeIP)
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

func startTAP(ifaceName, ifaceIP, fakeMAC, fakeIP string) error {
	iface, err := createIface(ifaceName)
	if err != nil {
		return errors.New(fmt.Sprintf("error occured while create iface: %v", err))
	}

	err = setupIface(ifaceName, ifaceIP)
	if err != nil {
		return errors.New(fmt.Sprintf("error occured while setup iface: %v", err))
	}

	fakeMACAddr, _ := net.ParseMAC(fakeMAC)
	fakeIPAddr := net.ParseIP(fakeIP)

	buffer := make([]byte, 1500)
	for {
		n, err := iface.Read(buffer)
		if err != nil {
			log.Printf("iface read failed: %v", err)
			continue
		}

		ethernetPacket := gopacket.NewPacket(buffer[:n], layers.LayerTypeEthernet, gopacket.Default)
		if arpLayer := ethernetPacket.Layer(layers.LayerTypeARP); arpLayer != nil {
			printPacketInHex("ARP REQUEST", buffer[:n])

			handleARPRequest(iface, arpLayer, fakeMACAddr, fakeIPAddr)
		}

		if icmpLayer := ethernetPacket.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			printPacketInHex("ICMP REQUEST", buffer[0:n])

			handleICMPRequest(iface, ethernetPacket, icmpLayer)
		}

		time.Sleep(time.Millisecond * 100)
	}
}

func handleICMPRequest(iface *water.Interface, packet gopacket.Packet, icmpLayer gopacket.Layer) {

	icmpPacket, _ := icmpLayer.(*layers.ICMPv4)

	if icmpPacket.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {

		icmpReplyPacket := &layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoReply,
			Id:       icmpPacket.Id,
			Seq:      icmpPacket.Seq,
		}

		ipPacket := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipPacket.DstIP, ipPacket.SrcIP = ipPacket.SrcIP, ipPacket.DstIP

		ethernetPacket := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ethernetPacket.DstMAC, ethernetPacket.SrcMAC = ethernetPacket.SrcMAC, ethernetPacket.DstMAC

		frame := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(frame, gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}, ethernetPacket, ipPacket, icmpReplyPacket, gopacket.Payload(icmpPacket.Payload))
		if err != nil {
			log.Printf("serialize layers failed: %v", err)
			return
		}

		printPacketInHex("ICMP REPLY", frame.Bytes())

		_, err = iface.Write(frame.Bytes())
		if err != nil {
			log.Printf("iface write failed: %v", err)
		}
	}
}

func handleARPRequest(iface *water.Interface, arpLayer gopacket.Layer, macAddr net.HardwareAddr, ipAddr net.IP) {
	arpPacket, _ := arpLayer.(*layers.ARP)

	arpReply := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   macAddr,
		SourceProtAddress: ipAddr.To4(),
		DstHwAddress:      arpPacket.SourceHwAddress,
		DstProtAddress:    arpPacket.SourceProtAddress,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       macAddr,
		DstMAC:       arpPacket.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}

	frame := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(frame, gopacket.SerializeOptions{}, ethernetLayer, arpReply)
	if err != nil {
		log.Printf("serialize layers failed: %v", err)
		return
	}

	printPacketInHex("ARP REPLY", frame.Bytes())

	_, err = iface.Write(frame.Bytes())
	if err != nil {
		log.Printf("ARP reply failed: %v", err)
	}
}

func createIface(ifaceName string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: ifaceName,
		},
	}
	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}

	return iface, nil
}

func setupIface(ifaceName, ifaceIP string) (err error) {
	cmd := exec.Command("ip", "link", "set", "dev", ifaceName, "up")
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("ip", "addr", "add", ifaceIP+"/24", "dev", ifaceName)
	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func printPacketInHex(name string, bytes []byte) {
	fmt.Printf("%s: %s: ", time.Now().Format("2006-01-02 15:04:05"), name)
	for _, b := range bytes {
		fmt.Printf("%02x ", b)
	}

	fmt.Println()
}
