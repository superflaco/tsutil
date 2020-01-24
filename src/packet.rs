use byteorder::{BigEndian, ByteOrder};

pub struct Packet {
    data: PacketData,
    header: u32,
}

impl Packet {
    pub fn new(data: PacketData) -> Packet {
        let header = BigEndian::read_u32(&data[0..4]);
        return Packet {
            data: data,
            header: header,
        };
    }

    pub fn with_cc(data: PacketData, cc: u8) -> PacketData {
        let mut updated = data;
        updated[3] = (data[3] & 0xF0) + (cc & 0xF);
        return updated;
    }

    pub fn create_packet_with_payload(
        tei: bool,
        pusi: bool,
        priority: bool,
        pid: u16,
        tsc: u8,
        afc: u8,
        cc: u8,
        payload: &[u8],
    ) -> PacketData {
        let mut data = Packet::create_packet(tei, pusi, priority, pid, tsc, afc, cc);
        let mut payload_len = payload.len();
        if payload_len > 184 {
            payload_len = 184;
        }
        for pos in 0..payload_len {
            data[4 + pos] = payload[pos];
        }
        return data;
    }

    pub fn create_packet(
        tei: bool,
        pusi: bool,
        priority: bool,
        pid: u16,
        tsc: u8,
        afc: u8,
        cc: u8,
    ) -> PacketData {
        let mut pkt: PacketData = [0xFF; 188];
        pkt[0] = 0x47;
        if !tei {
            pkt[1] = pkt[1] ^ 0x80;
        }
        if !pusi {
            pkt[1] = pkt[1] ^ 0x40;
        }
        if !priority {
            pkt[1] = pkt[1] ^ 0x20;
        }
        // 0xE0 preserves what was set above
        pkt[1] = pkt[1] & (0xE0 | (pid >> 8)) as u8;
        pkt[2] = pkt[2] & (pid & 0xFF) as u8;
        pkt[3] = ((tsc << 6) & 0xC0) + ((afc << 4) & 0x30) + (cc & 0xF);

        return pkt;
    }
}

pub type PacketData = [u8; 188];

pub trait PacketHeader {
    fn sync(&self) -> u8;
    fn tei(&self) -> bool;
    fn pusi(&self) -> bool;
    fn priority(&self) -> bool;
    fn pid(&self) -> u16;
    fn tsc(&self) -> u8;
    fn afc(&self) -> u8;
    fn has_adaptation_field(&self) -> bool;
    fn has_payload(&self) -> bool;
    fn cc(&self) -> u8;
}

impl PacketHeader for Packet {
    fn sync(&self) -> u8 {
        return self.header.sync();
    }
    fn tei(&self) -> bool {
        return self.header.tei();
    }
    fn pusi(&self) -> bool {
        return self.header.pusi();
    }
    fn priority(&self) -> bool {
        return self.header.priority();
    }
    fn pid(&self) -> u16 {
        return self.header.pid();
    }
    fn tsc(&self) -> u8 {
        return self.header.tsc();
    }
    fn afc(&self) -> u8 {
        return self.header.afc();
    }
    fn has_adaptation_field(&self) -> bool {
        return self.header.has_adaptation_field();
    }
    fn has_payload(&self) -> bool {
        return self.header.has_payload();
    }
    fn cc(&self) -> u8 {
        return self.header.cc();
    }
}

impl PacketHeader for u32 {
    fn sync(&self) -> u8 {
        return ((self & 0xff000000) >> 24) as u8;
    }
    fn tei(&self) -> bool {
        return 0 != self & 0x800000;
    }
    fn pusi(&self) -> bool {
        return 0 != self & 0x400000;
    }
    fn priority(&self) -> bool {
        return 0 != self & 0x200000;
    }
    fn pid(&self) -> u16 {
        return ((self & 0x1fff00) >> 8) as u16;
    }
    fn tsc(&self) -> u8 {
        return ((self & 0xc0) >> 6) as u8;
    }
    fn afc(&self) -> u8 {
        return ((self & 0x30) >> 4) as u8;
    }
    fn has_adaptation_field(&self) -> bool {
        return 0 != self.afc() & 0x2;
    }
    fn has_payload(&self) -> bool {
        return 0 != self.afc() & 0x1;
    }
    fn cc(&self) -> u8 {
        return (self & 0xf) as u8;
    }
}

pub trait AdaptationField {
    fn aflen(&self) -> u8;
    fn is_discontinuity(&self) -> bool;
    fn is_random_access(&self) -> bool;
    fn priority_stream(&self) -> bool;
    fn has_pcr(&self) -> bool;
    fn has_opcr(&self) -> bool;
    fn has_splice_countdown(&self) -> bool;
    fn has_transport_private_data(&self) -> bool;
    fn has_extension(&self) -> bool;
    fn pcr(&self) -> u64;
    fn pcr_nanos(&self) -> u64;
    fn opcr(&self) -> u64;
    fn opcr_nanos(&self) -> u64;
    fn splice_countdown(&self) -> u8;
    fn transport_private_data_len(&self) -> u8;
    fn transport_private_data(&self) -> &[u8];
    fn extension(&self) -> &[u8];
    fn stuffing(&self) -> &[u8];
}

fn read_pcr_data(buf: &[u8]) -> u64 {
    let high_int = BigEndian::read_u32(&buf[0..4]) as u64;
    let low_short = BigEndian::read_u16(&buf[4..6]) as u64;
    let upper = high_int << 1 + (low_short & 0x8000 >> 15);
    let lower = low_short & 0x1ff;
    /* println!(
        "\nhexpcr: {:X}{:X}{:X}{:X}{:X}{:X} high_int: {:X}, upper: {:X} lower: {:X}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], high_int,upper, lower
    );
    */
    return (upper * 300) + lower;
}

fn pcr_to_nanos(pcr: u64) -> u64 {
    return (pcr * 1_000_000_000) / 27_000_000;
}

impl AdaptationField for Packet {
    fn aflen(&self) -> u8 {
        return self.data[4];
    }
    fn is_discontinuity(&self) -> bool {
        return 0 != self.data[5] & 0x80;
    }
    fn is_random_access(&self) -> bool {
        return 0 != self.data[5] & 0x40;
    }
    fn priority_stream(&self) -> bool {
        return 0 != self.data[5] & 0x20;
    }
    fn has_pcr(&self) -> bool {
        return 0 != self.data[5] & 0x10;
    }
    fn has_opcr(&self) -> bool {
        return 0 != self.data[5] & 0x8;
    }
    fn has_splice_countdown(&self) -> bool {
        return 0 != self.data[5] & 0x4;
    }

    fn has_transport_private_data(&self) -> bool {
        return 0 != self.data[5] & 0x2;
    }

    fn has_extension(&self) -> bool {
        return 0 != self.data[5] & 0x1;
    }

    fn pcr(&self) -> u64 {
        if self.has_pcr() {
            return read_pcr_data(&self.data[6..13]);
        }
        return 0;
    }

    fn pcr_nanos(&self) -> u64 {
        return pcr_to_nanos(self.pcr());
    }
    fn opcr(&self) -> u64 {
        if self.has_pcr() {
            return read_pcr_data(&self.data[13..20]);
        } else {
            return self.pcr();
        }
    }

    fn opcr_nanos(&self) -> u64 {
        return pcr_to_nanos(self.opcr());
    }

    fn splice_countdown(&self) -> u8 {
        if self.has_splice_countdown() {
            if self.has_pcr() {
                if self.has_opcr() {
                    return self.data[20];
                } else {
                    return self.data[13];
                }
            } else {
                if self.has_opcr() {
                    return self.data[13];
                } else {
                    return self.data[6];
                }
            }
        } else {
            return 0;
        }
    }

    fn transport_private_data_len(&self) -> u8 {
        if self.has_transport_private_data() {
            if self.has_splice_countdown() {
                if self.has_pcr() {
                    if self.has_opcr() {
                        return self.data[21];
                    } else {
                        return self.data[14];
                    }
                } else {
                    if self.has_opcr() {
                        return self.data[14];
                    } else {
                        return self.data[7];
                    }
                }
            } else {
                if self.has_pcr() {
                    if self.has_opcr() {
                        return self.data[20];
                    } else {
                        return self.data[14];
                    }
                } else {
                    if self.has_opcr() {
                        return self.data[14];
                    } else {
                        return self.data[7];
                    }
                }
            }
        } else {
            return 0;
        }
    }

    fn transport_private_data(&self) -> &[u8] {
        if self.has_transport_private_data() {
            let trans_len = self.transport_private_data_len() as usize;
            if self.has_splice_countdown() {
                if self.has_pcr() {
                    if self.has_opcr() {
                        return &self.data[22..22 + trans_len];
                    } else {
                        return &self.data[15..15 + trans_len];
                    }
                } else {
                    if self.has_opcr() {
                        return &self.data[15..15 + trans_len];
                    } else {
                        return &self.data[8..8 + trans_len];
                    }
                }
            } else {
                if self.has_pcr() {
                    if self.has_opcr() {
                        return &self.data[21..21 + trans_len];
                    } else {
                        return &self.data[15..15 + trans_len];
                    }
                } else {
                    if self.has_opcr() {
                        return &self.data[15..15 + trans_len];
                    } else {
                        return &self.data[8..8 + trans_len];
                    }
                }
            }
        } else {
            return &[];
        }
    }

    fn extension(&self) -> &[u8] {
        // TODO: implement this once I need the data in it
        return &[];
    }
    fn stuffing(&self) -> &[u8] {
        // TODO: maybe let folks grab the stuffing someday, though not sure what the purpose would be
        return &[];
    }
}

pub trait Payload {
    fn payload_data(&self) -> &[u8];
}

impl Payload for Packet {
    fn payload_data(&self) -> &[u8] {
        let mut offset = 4;
        if self.has_adaptation_field() {
            offset += self.aflen() as usize;
        }
        return &self.data[offset..188];
    }
}
