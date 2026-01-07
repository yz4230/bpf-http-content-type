from os import path
from scapy.layers import inet, inet6


def main():
    dir_script = path.dirname(path.abspath(__file__))
    path_http_response = path.join(dir_script, "http_response.txt")
    with open(path_http_response, "rb") as f:
        http_response = f.read()

    packet = (
        inet6.IPv6(src="fc00::1", dst="fc00::3")
        / inet6.IPv6ExtHdrSegmentRouting(
            segleft=1,
            lastentry=2,
            addresses=["2001:db8::1", "2001:db8::2", "2001:db8::3"],
        )
        / inet6.IPv6(src="2001:db8::1", dst="2001:db8::2")
        / inet.TCP(sport=12345, dport=80)
        / http_response
    )
    packet.show()

    with open("packet.bin.local", "wb") as f:
        f.write(bytes(packet))


if __name__ == "__main__":
    main()
