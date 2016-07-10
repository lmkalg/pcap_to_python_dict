import sys
from argparse import ArgumentParser


# You need scapy installed to run this
from scapy.utils import PcapReader
import scapy.layers.inet  # Don't remove, it is being used.


def pcap_to_dict(pcap_filename, outfile=None):
    # Pick up only TCP messages
    messages = [seg for seg in PcapReader(pcap_filename) if "TCP" in seg]
    segments = []
    last_ack = {}
    for m in messages:
        segment = {}
        segment["src"] = m.sprintf("%IP.src%:%TCP.sport%")
        segment["dst"] = m.sprintf("%IP.dst%:%TCP.dport%")
        flags = m.sprintf("%TCP.flags%")
        segment["syn"] = "S" in flags
        segment["fin"] = "F" in flags
        segment["rst"] = "R" in flags
        # Acks are special. Not only the A bit must be set,
        # but also the seq number should increase
        if "A" in flags:
            conn_key = (segment["src"], segment["dst"])
            if conn_key in last_ack:
                old_ack = last_ack[conn_key]
            else:
                old_ack = m["TCP"].ack - 1
            last_ack[conn_key] = m["TCP"].ack
            segment["ack"] = old_ack != m["TCP"].ack
        else:
            segment["ack"] = False
        segments.append(segment)
    res = "[\n    "
    res += ",\n    ".join(str(seg) for seg in segments)
    res += "\n]"
    if outfile:
        with open(outfile, 'w') as f:
            f.write(res)
    else:
        sys.stdout.write(res)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('-f', dest='pcap_path', help="Path to the .pcap file.")
    parser.add_argument('-o', dest='out_fname', help="Output name.")

    args = parser.parse_args()

    if not args.pcap_path:
        parser.error("Missing .pcap file path")

    pcap_to_dict(args.pcap_path, outfile=args.out_fname)
