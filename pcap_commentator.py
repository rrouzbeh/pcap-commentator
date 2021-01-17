import argparse
from datetime import datetime
import json
import socket

import dpkt
from dpkt.compat import compat_ord
from pcapng import FileScanner
from pkg.writer import FileWriter


def mac_parser(eth):
    """
    Parse and convert src & dst Mac address in hex to string

        Args:
            eth: dpkt.ethernet.Ethernet
        Returns:
            tuple: (src_mac, dst_mac)
    """
    return (
        ':'.join('%02x' % compat_ord(b) for b in eth.src),
        ':'.join('%02x' % compat_ord(b) for b in eth.dst)
    )


def ip_parser(ip):
    """
    Parse and convert src & dst inet object to string

        Args:
            ip: dpkt.ethernet.Ethernet.data
        Returns:
            tuple: (src_ip, dst_ip)
    """
    if isinstance(ip, dpkt.ip.IP):
        try:
            return (
                socket.inet_ntop(socket.AF_INET, ip.src),
                socket.inet_ntop(socket.AF_INET, ip.dst)
            )

        except ValueError:
            return (
                socket.inet_ntop(socket.AF_INET6, ip.src),
                socket.inet_ntop(socket.AF_INET6, ip.dst)
            )
    else:
        return (None, None)


def parse_packet(packet_data):
    """
    Parse ip and mac address from pcap packet data

        Args:
            packet_data: packet.packet_data
        Returns:
            tuple: (src_mac, dst_mac, src_ip, dst_ip)
    """
    try:
        eth = dpkt.ethernet.Ethernet(packet_data)
        return mac_parser(eth) + ip_parser(eth.data)
    except TypeError:
        return (None, None, None, None)


def pacp_reader(pcap, packet_number):
    """
    Print out information about requested packet in a pcap

        Args:
            pcap: a list of pcap blocks
            packet_number: requested packet number

    """
    try:
        # select requested packet from pcap list
        packet = pcap[int(packet_number)+1]

        src_mac, dst_mac, src_ip, dst_ip = parse_packet(packet.packet_data)

        decoded_packet = {
            "timestamp": datetime.utcfromtimestamp(
                packet.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "interface": packet.interface.options.get("if_name"),
            "comment": packet.options.get("opt_comment")
        }
        print(json.dumps(decoded_packet, indent=4))
    except IndexError:
        print(
            f"This pcap file has {len(pcap)} packets please "
            "enter a currect packet number"
        )
    except ValueError:
        print("Please check your inputs")


def pcap_writer(pcap, packet_number, output_file, comment):
    """
    write a new pcapng file after comment inserted in requested packet

        Args:
            pcap: a list of pcap blocks
            packet_number: requested packet number
            output_file: new pcapng path
            comment: new Comment

    """
    try:
        # Pcapng SectionHeader
        shb = pcap.pop(0)

        # delete InterfaceDescription to prevent duplication
        del pcap[0]

        # add Comment to requested packet
        pcap[int(packet_number)-1].options["opt_comment"] = comment

        # create new pcapng file
        with open(output_file, "wb") as out:
            writer = FileWriter(out, shb)
            for packet in pcap:
                writer.write_block(packet)
            out.close()
    except IndexError:
        print(
            f"This pcap file has {len(pcap)} packets please "
            "enter a currect packet number"
        )
    except ValueError:
        print("Please check your inputs")


def main(args):
    try:
        pcap = list(FileScanner(args.input_file))

        if args.mode == "read":
            pacp_reader(pcap, args.packet_number)
        if args.mode == "write":
            pcap_writer(pcap, args.packet_number,
                        args.output_file, args.comment)
    except ValueError:
        print(
            "Could not open input file "
            "- please specify a currect pcapng file"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PCAP COMMENTATOR: Read and Add Comment to a packet of a pcapng")
    parser.add_argument('mode',
                        choices=['read', 'write'],
                        help="Mode: (read | write)")
    parser.add_argument('-i', dest="input_file",
                        type=argparse.FileType("rb"),
                        default="./test.pcapng",
                        help="Path to pcapng source file(/path_to/input.pcapng)")
    parser.add_argument('-o', dest="output_file",
                        default="./out.pcapng",
                        help="Path to pcapng destination file(/path_to/output.pcapng)")
    parser.add_argument('-n', dest="packet_number",
                        default="1",
                        help="Packet number")
    parser.add_argument('-c', dest="comment",
                        default="TEST COMMENT",
                        help="Text Comment")

    main(parser.parse_args())
