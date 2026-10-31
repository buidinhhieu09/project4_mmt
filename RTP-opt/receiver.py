import sys, socket, struct, argparse, zlib
START = 0; END = 1; DATA = 2; ACK = 3; MAX_PACKET_SIZE = 1472; HEADER_SIZE = 16

def compute_checksum(pkt_type, seq_num, length, data):
    return zlib.crc32(struct.pack('!III', pkt_type, seq_num, length) + data) & 0xffffffff

def create_ack(seq_num):
    return struct.pack('!IIII', ACK, seq_num, 0, compute_checksum(ACK, seq_num, 0, b""))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('receiver_ip'); parser.add_argument('receiver_port', type=int); parser.add_argument('window_size', type=int)
    args = parser.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.receiver_ip, args.receiver_port))
    expected_seq = 0; buffer = {}; started = False

    while True:
        pkt, addr = sock.recvfrom(MAX_PACKET_SIZE)
        if len(pkt) < HEADER_SIZE: continue
        pkt_type, seq_num, length, rec_checksum = struct.unpack('!IIII', pkt[:HEADER_SIZE])
        data = pkt[HEADER_SIZE:HEADER_SIZE+length]
        if rec_checksum != compute_checksum(pkt_type, seq_num, length, data): continue 

        if pkt_type == START:
            if not started: started = True; expected_seq = 1
            sock.sendto(create_ack(expected_seq), addr); continue
        if not started: continue
        if pkt_type == END: sock.sendto(create_ack(seq_num + 1), addr); break
        
        if pkt_type == DATA:
            if seq_num >= expected_seq + args.window_size: continue
            if seq_num == expected_seq:
                sys.stdout.buffer.write(data); expected_seq += 1
                while expected_seq in buffer:
                    sys.stdout.buffer.write(buffer.pop(expected_seq)); expected_seq += 1
                sys.stdout.buffer.flush()
            elif seq_num > expected_seq: buffer[seq_num] = data
            sock.sendto(create_ack(seq_num), addr)

if __name__ == "__main__": main()