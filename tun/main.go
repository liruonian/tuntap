package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"github.com/urfave/cli"
	"log"
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
	}

	app.Action = func(c *cli.Context) error {
		ifaceName := c.String("n")
		ifaceIP := c.String("ip")

		return startTUN(ifaceName, ifaceIP)
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

func startTUN(ifaceName, ifaceIP string) error {
	iface, err := createIface(ifaceName)
	if err != nil {
		return errors.New(fmt.Sprintf("error occured while create iface: %v", err))
	}

	err = setupIface(ifaceName, ifaceIP)
	if err != nil {
		return errors.New(fmt.Sprintf("error occured while setup iface: %v", err))
	}

	buffer := make([]byte, 1500)
	for {
		n, err := iface.Read(buffer)
		if err != nil {
			log.Printf("iface read failed: %v", err)
			continue
		}

		ethernetPacket := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.Default)

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

		frame := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(frame, gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}, ipPacket, icmpReplyPacket, gopacket.Payload(icmpPacket.Payload))
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

func createIface(ifaceName string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
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
	fmt.Printf("%s %s: ", time.Now().Format("2006-01-02 15:04:05"), name)
	for _, b := range bytes {
		fmt.Printf("%02x ", b)
	}

	fmt.Println()
}
