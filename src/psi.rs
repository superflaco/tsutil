use crate::packet::{Packet, PacketData, PacketHeader, Payload};
use byteorder::{BigEndian, ByteOrder};

pub trait PSI {
    fn tables(&self) -> Option<&[u8]>;
}

impl PSI for Packet {
    fn tables(&self) -> Option<&[u8]> {
        if self.has_payload() {
            let data = self.payload_data();
            let padding = data[0] as usize;
            //println!("table padding {}", padding + 1);
            return Some(&data[padding + 1..]);
        }
        return None;
    }
}

pub trait TableHeader {
    fn table_id(&self) -> u8;
    fn has_syntax_section(&self) -> bool;
    fn private(&self) -> bool;
    fn section_length(&self) -> u16;
    fn section_data(&self) -> &[u8];
    fn next(&self) -> Option<&[u8]>;
}

impl TableHeader for &[u8] {
    fn table_id(&self) -> u8 {
        return self[0];
    }
    fn has_syntax_section(&self) -> bool {
        return (self[1] & 0x80) != 0;
    }
    fn private(&self) -> bool {
        return (self[1] & 0x40) != 0;
    }
    fn section_length(&self) -> u16 {
        return 0x3ff & BigEndian::read_u16(&self[1..3]);
    }
    fn section_data(&self) -> &[u8] {
        return &self[..3 + self.section_length() as usize];
    }

    fn next(&self) -> Option<&[u8]> {
        if self.len() > 3 + self.section_length() as usize {
            let next = &self[3 + self.section_length() as usize..];
            // only return next if table ID is not filler
            if next.table_id() < 0xFF {
                return Some(next);
            }
        }
        return None;
    }
}

pub trait TableSyntaxSection {
    fn valid_syntax(&self) -> bool;
    fn table_id_ext(&self) -> u16;
    fn version(&self) -> u8;
    fn current(&self) -> bool;
    fn section_num(&self) -> u8;
    fn last_section_num(&self) -> u8;
    fn table_data(&self) -> &[u8];
    fn crc32(&self) -> u32;
}

impl TableSyntaxSection for &[u8] {
    fn valid_syntax(&self) -> bool {
        return (self[5] & 0xC0) == 0xC0;
    }
    fn table_id_ext(&self) -> u16 {
        return BigEndian::read_u16(&self[3..5]);
    }
    fn version(&self) -> u8 {
        return (self[5] >> 1) & 0x1F;
    }
    fn current(&self) -> bool {
        return (self[5] & 1) == 1;
    }
    fn section_num(&self) -> u8 {
        return self[6];
    }
    fn last_section_num(&self) -> u8 {
        return self[7];
    }
    fn table_data(&self) -> &[u8] {
        let table_len = self.len();
        let crc_idx = table_len - 4;
        return &self[8..crc_idx];
    }
    fn crc32(&self) -> u32 {
        let table_len = self.len();
        let crc_idx = table_len - 4;
        return BigEndian::read_u32(&self[crc_idx..table_len]);
    }
}

pub fn create_pat_packet(pids: &[u16], cc: u8) -> PacketData {
    let mut pat = Packet::create_packet(false, true, false, 0, 0, 1, cc);
    let pid_count = pids.len();
    // pointer byte comes 5 bytes into the 188 byte packet
    let pointer = 188 - 5 - (16 * pid_count);
    //println!("table pointer {}" ,pointer);
    pat[4] = pointer as u8;
    let mut prog_num = 0;
    for pid in pids.iter() {
        let offset = pointer + 5 /* 5 bytes before pointer field */ + (16 * prog_num);
        prog_num = prog_num + 1;
        insert_pat_payload(offset, prog_num, *pid, &mut pat);
        //println!("pat packet hex {}", hex::encode_upper(&pat[..]))
    }
    return pat;
}

fn insert_pat_payload(offset: usize, num: usize, pid: u16, pat: &mut PacketData) {
    pat[offset] = 0; // table id
    pat[offset + 1] = 0x80 | 0x30; // section syntax & reserved bits
    pat[offset + 2] = 13; // 13 byte section length
    pat[offset + 3] = 0; // table id extension is 1 first byte
    pat[offset + 4] = 1; // table id extension is 1 second byte
    pat[offset + 5] = 0xC1; // reserved, version 0 and current
    pat[offset + 6] = 0; // section number 0
    pat[offset + 7] = 0; // last section number 0
    pat[offset + 8] = (num >> 8) as u8; // program number manually converting u16 to big endian bytes
    pat[offset + 9] = (num & 0xFF) as u8;
    pat[offset + 10] = 0xE0 | (pid >> 8) as u8; // pid manually converting u16 to big endian bytes
    pat[offset + 11] = (pid & 0xFF) as u8;
    // the calc function drops the last 4 bytes when doing the checksum, so leaving them on here
    let crc_data = &pat[offset..offset + 16];
    //println!("crc_data {}", hex::encode_upper(crc_data));
    let crc = calc_crc32(crc_data);
    BigEndian::write_u32(&mut pat[offset + 12..offset + 16], crc)
}

pub trait PAT {
    fn valid_pat(&self) -> bool;
    fn program_num(&self) -> u16;
    fn program_map_pid(&self) -> u16;
    fn next_program(&self) -> Option<&[u8]>;
}

impl PAT for &[u8] {
    fn valid_pat(&self) -> bool {
        return (&self[2] & 0xE0) == 0xE0;
    }
    fn program_num(&self) -> u16 {
        return BigEndian::read_u16(&self[0..2]);
    }
    fn program_map_pid(&self) -> u16 {
        return 0x1FFF & BigEndian::read_u16(&self[2..4]);
    }
    fn next_program(&self) -> Option<&[u8]> {
        if self.len() >= 8 {
            return Some(&self[4..]);
        }
        return None;
    }
}

pub fn create_pmt_packet(pid: u16, pid_type_pairs: &[(u16, u8)], cc: u8) -> PacketData {
    let mut pmt = Packet::create_packet(false, true, false, pid, 0, 1, cc);
    let stream_count = pid_type_pairs.len();
    // pointer byte comes 5 bytes into the 188 byte packet and pmt had 16 bytes plus 5 bytes for each elementary stream with no descriptors
    let pointer = 188 - 5 - 16 - (5 * stream_count);
    //println!("table pointer {}", pointer);
    pmt[4] = pointer as u8;
    let offset = pointer + 5 /* 5 bytes before pointer field */ ;

    pmt[offset] = 2; // table id
    pmt[offset + 1] = 0x80 | 0x30; // section syntax & reserved bits
    pmt[offset + 2] = 13 + (5 * stream_count as u8); // 13 byte section length plus 5 bytes per stream
    pmt[offset + 3] = 0; // table id extension is 1 so first byte is then 0
    pmt[offset + 4] = 1; // table id extension is 1 second byte
    pmt[offset + 5] = 0xC1; // reserved, version 0 and current
    pmt[offset + 6] = 0; // section number 0
    pmt[offset + 7] = 0; // last section number 0
    pmt[offset + 8] = 0xFF; // reserved plus high bits of filler PCR pid
    pmt[offset + 9] = 0xFF; // low bits of filler PCR pid
    pmt[offset + 10] = 0xF0; // reserved bits and zero program info
    pmt[offset + 11] = 0; // zero program info
    let mut pair_num = 0;
    for pair in pid_type_pairs.iter() {
        pmt[offset + 12 + pair_num] = pair.1;
        pmt[offset + 13 + pair_num] = 0xE0 + ((pair.0 >> 8) & 0x1F) as u8; // reserved plus high bits of ES pid
        pmt[offset + 14 + pair_num] = (pair.0 & 0xFF) as u8; // low bits of ES pid
        pmt[offset + 15 + pair_num] = 0xF0; // reserved bits and zero program info
        pmt[offset + 16 + pair_num] = 0; // zero program info
        pair_num = pair_num + 1;
    }

    // the calc function drops the last 4 bytes when doing the checksum, so leaving them on here
    let crc_data = &pmt[offset..offset + 16 + (5 * stream_count)];
    let crc = calc_crc32(crc_data);
    BigEndian::write_u32(
        &mut pmt[offset + 12 + (5 * stream_count)..offset + 16 + (5 * stream_count)],
        crc,
    );
    return pmt;
}

pub trait PMT {
    fn valid_pmt(&self) -> bool;
    fn pcr_pid(&self) -> u16;
    fn program_info_len(&self) -> u16;
    fn descriptor_data(&self) -> Option<&[u8]>;
    fn elementary_streams(&self) -> &[u8];
}

impl PMT for &[u8] {
    fn valid_pmt(&self) -> bool {
        return (&self[0] & 0xE0) == 0xE0 && (&self[2] & 0xF0) == 0xF0;
    }
    fn pcr_pid(&self) -> u16 {
        return 0x1FFF & BigEndian::read_u16(&self[0..2]);
    }
    fn program_info_len(&self) -> u16 {
        return 0x3FF & BigEndian::read_u16(&self[2..4]);
    }
    fn descriptor_data(&self) -> Option<&[u8]> {
        let desc_len = self.program_info_len() as usize;
        if desc_len > 0 {
            return Some(&self[4..4 + desc_len]);
        }
        return None;
    }
    fn elementary_streams(&self) -> &[u8] {
        let desc_len = self.program_info_len() as usize;
        return &self[4 + desc_len..];
    }
}

pub trait ElementaryStream {
    fn valid_stream(&self) -> bool;
    fn stream_type(&self) -> u8;
    fn stream_pid(&self) -> u16;
    fn es_info_len(&self) -> u16;
    fn es_info(&self) -> &[u8];
    fn next_stream(&self) -> Option<&[u8]>;
}

impl ElementaryStream for &[u8] {
    fn valid_stream(&self) -> bool {
        return (&self[1] & 0xE0) == 0xE0 && (&self[3] & 0xF0) == 0xF0;
    }

    fn stream_type(&self) -> u8 {
        return self[0];
    }
    fn stream_pid(&self) -> u16 {
        return 0x1FFF & BigEndian::read_u16(&self[1..3]);
    }
    fn es_info_len(&self) -> u16 {
        return 0x3FF & BigEndian::read_u16(&self[3..5]);
    }
    fn es_info(&self) -> &[u8] {
        return &self[5..5 + self.es_info_len() as usize];
    }
    fn next_stream(&self) -> Option<&[u8]> {
        if self.len() > 5 + self.es_info_len() as usize {
            let next = &self[5 + self.es_info_len() as usize..];
            // only return next if stream type is not filler
            if next.stream_type() < 0xFF {
                return Some(next);
            }
        }
        return None;
    }
}

pub fn calc_crc32(section_data: &[u8]) -> u32 {
    let section_len = section_data.len();
    if section_len >= 4 {
        let mut crc32 = 0xffffffff;
        let to_sum = &section_data[0..section_len - 4];
        let mut byte_pos = 0;
        for b in to_sum.iter() {
            let mut dat = *b;
            for _ in 0..8 {
                if (crc32 >= 0x80000000) != (dat >= 0x80) {
                    crc32 = (crc32 << 1) ^ 0x04C11DB7;
                } else {
                    crc32 = crc32 << 1;
                }
                dat <<= 1;
            }
            byte_pos = byte_pos + 1;
        }
        //println!("crc for {} was {}", hex::encode_upper(to_sum), crc32);
        return crc32;
    }
    return 0;
}
