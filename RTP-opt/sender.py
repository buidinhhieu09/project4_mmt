import sys, socket, struct, time, argparse, zlib
START = 0; END = 1; DATA = 2; ACK = 3; MAX_PACKET_SIZE = 1472; HEADER_SIZE = 16; MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE; TIMEOUT = 0.5 

def compute_checksum(pkt_type, seq_num, length, data):
    return zlib.crc32(struct.pack('!III', pkt_type, seq_num, length) + data) & 0xffffffff

def create_packet(pkt_type, seq_num, data=b""):
    length = len(data)
    return struct.pack('!IIII', pkt_type, seq_num, length, compute_checksum(pkt_type, seq_num, length, data)) + data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('receiver_ip'); parser.add_argument('receiver_port', type=int); parser.add_argument('window_size', type=int)
    args = parser.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    dest = (args.receiver_ip, args.receiver_port)
    message = sys.stdin.buffer.read()
    chunks = [message[i:i+MAX_DATA_SIZE] for i in range(0, len(message), MAX_DATA_SIZE)]
    
    while True:
        sock.sendto(create_packet(START, 0), dest)
        try:
            ack_pkt, _ = sock.recvfrom(MAX_PACKET_SIZE)
            if struct.unpack('!IIII', ack_pkt[:HEADER_SIZE])[0] == ACK and struct.unpack('!IIII', ack_pkt[:HEADER_SIZE])[1] == 1: break
        except socket.timeout: continue

    base = 1; next_seq_num = 1; window = {}; acked_packets = set()
    while base <= len(chunks):
        while next_seq_num < base + args.window_size and next_seq_num <= len(chunks):
            window[next_seq_num] = create_packet(DATA, next_seq_num, chunks[next_seq_num - 1])
            sock.sendto(window[next_seq_num], dest)
            next_seq_num += 1
        try:
            ack_pkt, _ = sock.recvfrom(MAX_PACKET_SIZE)
            ack_type, ack_seq, _, _ = struct.unpack('!IIII', ack_pkt[:HEADER_SIZE])
            if ack_type == ACK:
                acked_packets.add(ack_seq)
                while base in acked_packets: base += 1
        except socket.timeout:
            for seq in range(base, next_seq_num):
                if seq not in acked_packets: sock.sendto(window[seq], dest)

    end_time = time.time() + 0.5
    while time.time() < end_time:
        sock.sendto(create_packet(END, next_seq_num), dest)
        try:
            sock.settimeout(end_time - time.time())
            ack_pkt, _ = sock.recvfrom(MAX_PACKET_SIZE)
            if struct.unpack('!IIII', ack_pkt[:HEADER_SIZE])[0] == ACK and struct.unpack('!IIII', ack_pkt[:HEADER_SIZE])[1] == next_seq_num + 1: break
        except socket.timeout: break
    sock.close()

if __name__ == "__main__": main()