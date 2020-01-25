pub mod packet;
pub mod psi;

#[cfg(test)]
mod tests {

    use crate::packet::{AdaptationField, Packet, PacketHeader, Payload};
    use crate::psi::{
        calc_crc32, create_pat_packet, create_pmt_packet, ElementaryStream, TableHeader,
        TableSyntaxSection, PAT, PMT, PSI,
    };

    fn hex_to_bin<T: AsRef<[u8]>>(hex: T) -> [u8; 188] {
        let mut pat_data_bin = [0u8; 188];
        assert_eq!(hex::decode_to_slice(hex, &mut pat_data_bin), Ok(()));
        return pat_data_bin;
    }

    #[test]
    fn validate_pat() {
        let pat_data_hex = "474000100000B00D0001C100000001F0002AB104B2FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let pat_data_bin = hex_to_bin(pat_data_hex);
        let pat_pkt = Packet::new(pat_data_bin);
        assert_eq!(pat_pkt.sync(), 0x47);
        assert_eq!(pat_pkt.pid(), 0);
        assert_eq!(pat_pkt.has_adaptation_field(), false);
        assert_eq!(pat_pkt.has_payload(), true);
        let tables = pat_pkt.tables().unwrap();
        assert_eq!(tables.table_id(), 0x0);
        assert_eq!(tables.has_syntax_section(), true);
        let pat_section = tables.section_data();
        assert_eq!(pat_section.table_id_ext(), 1);
        assert_eq!(pat_section.valid_syntax(), true);
        assert_eq!(pat_section.version(), 0);
        assert_eq!(pat_section.current(), true);
        assert_eq!(calc_crc32(pat_section), pat_section.crc32());
        let pat = pat_section.table_data();
        assert_eq!(pat.valid_pat(), true);
        assert_eq!(pat.program_num(), 1);
        assert_eq!(pat.program_map_pid(), 0x1000);
    }

    #[test]
    fn validate_pmt() {
        let pmt_data_hex = "475000100002B0120001C10000E100F0001BE100F00015BD4D56FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let pmt_pkt = Packet::new(hex_to_bin(pmt_data_hex));
        assert_eq!(pmt_pkt.sync(), 0x47);
        assert_eq!(pmt_pkt.pid(), 0x1000);
        assert_eq!(pmt_pkt.has_adaptation_field(), false);
        assert_eq!(pmt_pkt.has_payload(), true);
        let tables = pmt_pkt.tables().unwrap();
        assert_eq!(tables.table_id(), 0x2);
        assert_eq!(tables.has_syntax_section(), true);
        let pmt_section = tables.section_data();
        assert_eq!(pmt_section.table_id_ext(), 1);
        assert_eq!(calc_crc32(pmt_section), pmt_section.crc32());
        let pmt = pmt_section.table_data();
        assert_eq!(pmt.valid_pmt(), true);
        assert_eq!(pmt.pcr_pid(), 256);
        assert_eq!(pmt.descriptor_data(), None);
        let es = pmt.elementary_streams();
        println!("streams {}", hex::encode_upper(es));

        assert_eq!(es.valid_stream(), true);
        assert_eq!(es.stream_type(), 27);
        assert_eq!(es.stream_pid(), 256);
    }
    #[test]
    fn validate_payload() {
        let payload_data_hex = "47410030075000007B0C7E00000001E0000080C00A31000912F9110007D8610000000109F00000000167F40028919B280F0044FC4E0220000003002000000601E30632C00000000168EBE3C9200000010605FFFFAADC45E9BDE6D948B7962CD820D923EEEF78323634202D20636F7265203135352072323931372030613834643938202D20482E3236342F4D5045472D342041564320636F646563202D20436F70796C65667420323030332D32303138202D20687474703A2F2F7777";
        let payload_pkt = Packet::new(hex_to_bin(payload_data_hex));
        assert_eq!(payload_pkt.sync(), 0x47);
        assert_eq!(payload_pkt.pid(), 0x100);
        assert_eq!(payload_pkt.has_adaptation_field(), true);
        assert_eq!(payload_pkt.has_payload(), true);
        let payload_data = payload_pkt.payload_data();
        assert_eq!(payload_pkt.has_pcr(), true);
        println!(
            "aflen: {}, payload len: {}, data {}",
            payload_pkt.aflen(),
            payload_data.len(),
            hex::encode_upper(payload_data)
        );
    }

    #[test]
    fn synth_packet() {
        let raw_pkt = Packet::create_packet(false, true, false, 0, 0, 1, 9);
        //println!("raw {}", hex::encode_upper(&raw_pkt[..]));
        let synth_pkt = Packet::new(raw_pkt);
        assert_eq!(synth_pkt.sync(), 0x47);
        assert_eq!(synth_pkt.tei(), false);
        assert_eq!(synth_pkt.pusi(), true);
        assert_eq!(synth_pkt.priority(), false);
        assert_eq!(synth_pkt.pid(), 0);
        assert_eq!(synth_pkt.tsc(), 0);
        assert_eq!(synth_pkt.afc(), 1);
        assert_eq!(synth_pkt.cc(), 9);
        let updated_pkt = Packet::new(Packet::with_cc(raw_pkt, 3));
        assert_eq!(updated_pkt.cc(), 3);
    }

    #[test]
    fn synth_packet_with_large_payload() {
        let large_payload: [u8;184] = [0xBB; 184];
        let raw_pkt = Packet::create_packet_with_payload(false, true, false, 0, 0, 1, 9, &large_payload);
        println!("raw {}", hex::encode_upper(&raw_pkt[..]));
        let synth_pkt = Packet::new(raw_pkt);
        assert_eq!(synth_pkt.sync(), 0x47);
        assert_eq!(synth_pkt.tei(), false);
        assert_eq!(synth_pkt.pusi(), true);
        assert_eq!(synth_pkt.priority(), false);
        assert_eq!(synth_pkt.pid(), 0);
        assert_eq!(synth_pkt.tsc(), 0);
        assert_eq!(synth_pkt.afc(), 1);
        assert_eq!(synth_pkt.cc(), 9);
        assert_eq!(synth_pkt.has_adaptation_field(), false);
        let updated_pkt = Packet::new(Packet::with_cc(raw_pkt, 3));
        assert_eq!(updated_pkt.cc(), 3);
    }
    #[test]
    fn synth_packet_with_small_payload() {
        let small_payload: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let raw_pkt = Packet::create_packet_with_payload(false, true, false, 0, 0, 1, 9, &small_payload); 
        let synth_pkt = Packet::new(raw_pkt);
        println!("raw {}", hex::encode_upper(&raw_pkt[..]));
        assert_eq!(synth_pkt.sync(), 0x47);
        assert_eq!(synth_pkt.tei(), false);
        assert_eq!(synth_pkt.pusi(), true);
        assert_eq!(synth_pkt.priority(), false);
        assert_eq!(synth_pkt.pid(), 0);
        assert_eq!(synth_pkt.tsc(), 0);
        assert_eq!(synth_pkt.afc(), 3);
        assert_eq!(synth_pkt.cc(), 9);
        assert_eq!(synth_pkt.has_adaptation_field(), true);
        assert_eq!(synth_pkt.aflen(), 175);
        let updated_pkt = Packet::new(Packet::with_cc(raw_pkt, 3));
        assert_eq!(updated_pkt.cc(), 3);
        assert_eq!(updated_pkt.has_adaptation_field(), true);
        assert_eq!(updated_pkt.aflen(), 175);
    }

    #[test]
    fn synth_pat() {
        let raw_pkt = create_pat_packet(&[123, 456], 9);
        //println!("raw {}", hex::encode_upper(&raw_pkt[..]));
        let synth_pkt = Packet::new(raw_pkt);
        assert_eq!(synth_pkt.sync(), 0x47);
        assert_eq!(synth_pkt.tei(), false);
        assert_eq!(synth_pkt.pusi(), true);
        assert_eq!(synth_pkt.priority(), false);
        assert_eq!(synth_pkt.pid(), 0);
        assert_eq!(synth_pkt.tsc(), 0);
        assert_eq!(synth_pkt.afc(), 1);
        assert_eq!(synth_pkt.cc(), 9);
        assert_eq!(synth_pkt.has_adaptation_field(), false);
        assert_eq!(synth_pkt.has_payload(), true);
        let tables = synth_pkt.tables().unwrap();
        //println!("tables {}", hex::encode_upper(tables));
        assert_eq!(tables.table_id(), 0x0);
        assert_eq!(tables.has_syntax_section(), true);
        let pat_section = tables.section_data();
        assert_eq!(pat_section.table_id_ext(), 1);
        assert_eq!(pat_section.valid_syntax(), true);
        assert_eq!(pat_section.version(), 0);
        assert_eq!(pat_section.current(), true);
        //println!("section {}", hex::encode_upper(pat_section));

        assert_eq!(calc_crc32(pat_section), pat_section.crc32());
        let pat = pat_section.table_data();
        assert_eq!(pat.valid_pat(), true);
        assert_eq!(pat.program_num(), 1);
        assert_eq!(pat.program_map_pid(), 123);

        let next_table = tables.next().unwrap();
        let next_section = next_table.section_data();
        assert_eq!(next_section.table_id_ext(), 1);
        assert_eq!(next_section.valid_syntax(), true);
        assert_eq!(next_section.version(), 0);
        assert_eq!(next_section.current(), true);
        // println!("next section {}", hex::encode_upper(next_section));

        assert_eq!(calc_crc32(next_section), next_section.crc32());
        let next_pat = next_section.table_data();
        assert_eq!(next_pat.valid_pat(), true);
        assert_eq!(next_pat.program_num(), 2);
        assert_eq!(next_pat.program_map_pid(), 456);
    }

    #[test]
    fn synth_pmt() {
        let raw_pkt = create_pmt_packet(0x1000, &[(256, 27)], 9);
        //println!("raw {}", hex::encode_upper(&raw_pkt[..]));
        let pmt_pkt = Packet::new(raw_pkt);
        assert_eq!(pmt_pkt.sync(), 0x47);
        assert_eq!(pmt_pkt.pid(), 0x1000);
        assert_eq!(pmt_pkt.has_adaptation_field(), false);
        assert_eq!(pmt_pkt.has_payload(), true);
        let tables = pmt_pkt.tables().unwrap();
        assert_eq!(tables.table_id(), 0x2);
        assert_eq!(tables.has_syntax_section(), true);
        let pmt_section = tables.section_data();
        assert_eq!(pmt_section.table_id_ext(), 1);
        //println!("section {}", hex::encode_upper(pmt_section));

        assert_eq!(calc_crc32(pmt_section), pmt_section.crc32());
        let pmt = pmt_section.table_data();
        assert_eq!(pmt.valid_pmt(), true);
        assert_eq!(pmt.pcr_pid(), 0x1FFF);
        assert_eq!(pmt.descriptor_data(), None);
        let es = pmt.elementary_streams();
        //println!("streams {}", hex::encode_upper(es));

        assert_eq!(es.valid_stream(), true);
        assert_eq!(es.stream_type(), 27);
        assert_eq!(es.stream_pid(), 256);
    }
}
/*
Full Packet 474011100042F0250001C10000FF01FF0001FC80144812010646466D70656709536572766963653031777C43CAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
sync: 47, pid: 17, tei:false, pusi:true, priority:false tsc: 0, afc: 1, cc: 0
Full Packet 474000100000B00D0001C100000001F0002AB104B2FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
sync: 47, pid: 0, tei:false, pusi:true, priority:false tsc: 0, afc: 1, cc: 0Checksumming 0001C100000001F000, ieee:55B70B85, koopman: DB8114F2 cast: F4D88CC2
other crc data hex0001C100000001F000

PAT program 1 has PID 4096 provided CRC32 2AB104B2 calculated CRC32 55B70B85 other calculated CRC32 D59979A9

Full Packet 475000100002B0120001C10000E100F0001BE100F00015BD4D56FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
sync: 47, pid: 4096, tei:false, pusi:true, priority:false tsc: 0, afc: 1, cc: 0
Full Packet 47410030075000007B0C7E00000001E0000080C00A31000912F9110007D8610000000109F00000000167F40028919B280F0044FC4E0220000003002000000601E30632C00000000168EBE3C9200000010605FFFFAADC45E9BDE6D948B7962CD820D923EEEF78323634202D20636F7265203135352072323931372030613834643938202D20482E3236342F4D5045472D342041564320636F646563202D20436F70796C65667420323030332D32303138202D20687474703A2F2F7777
sync: 47, pid: 256, tei:false, pusi:true, priority:false tsc: 0, afc: 11, cc: 0
*/
