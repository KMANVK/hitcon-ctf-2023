def add_adts(raw_packet):
    profile = 2#  //AAC LC
    freqIdx = 4#  //44.1KHz
    chanCfg = 2#  //CPE
    packetLen = len(raw_packet) + 7

    # fill in ADTS data
    packet = bytearray(7)
    packet[0] = 0xFF
    packet[1] = 0xF9
    packet[2] = (((profile-1)<<6) + (freqIdx<<2) +(chanCfg>>2))
    packet[3] = (((chanCfg&3)<<6) + (packetLen>>11))
    packet[4] = ((packetLen&0x7FF) >> 3)
    packet[5] = (((packetLen&7)<<5) + 0x1F)
    packet[6] = 0xFC
    return packet + raw_packet

f = open('out.aac', 'wb')

i = 0
for line in open('raw_hex', 'r'):
    line_bytes = bytes.fromhex(line)
    packet = line_bytes[12:]
    packet = add_adts(packet)
    f.write(packet)
