use std::fs;
use std::io::Result;
use std::fs::File;
use std::fs::Metadata;
use std::io::Read;
use std::io::BufReader;
use std::io::Seek;
use std::io::SeekFrom;
use std::option::Option;

extern crate crypto;
use crypto::digest::Digest;

fn main() {
    match fs::read_dir("/Users/alexeyakhunov/Library/Application Support/Bitcoin/blocks") {
        Err(why) => println!("{:?}", why),
        Ok(dir_entries) => {
            let mut block_number: u32 = 0;
            for dir_entry in dir_entries {
                block_number = parse_file(dir_entry, block_number);
            }
        }
    };
}

fn parse_file(dir_entry: Result<fs::DirEntry>, initial_block: u32) -> u32 {
    match dir_entry {
        Err(why) => {
            println!("{:?}", why);
            0
        },
        Ok(path) => {
            let filepath = path.path();
            let filename = filepath.file_name().unwrap().to_str().unwrap();
            if filename.starts_with("blk") && filename.ends_with(".dat") {
                let metadata = fs::metadata(&filepath).unwrap();
                let f = File::open(&filepath);
                match f {
                    Err(why) => {
                        println!("{:?}", why);
                        0
                    }
                    Ok(mut file) => {
                        println!("Opened {:?}", filename);
                        read_blocks(&mut file, metadata.len(), initial_block)
                    },
                }
            } else {
                0
            }
        }
    }
}

fn read_blocks(file: &mut File, filesize: u64, initial_block: u32) -> u32 {
    let mut reader = BufReader::new(file);
    let mut buf: [u8; 4] = [0u8; 4];
    let mut block: Vec<u8> = vec![];
    let mut block_number: u32 = initial_block;
    loop {
        match reader.read_exact(&mut buf) {
            Err(_) => break,
            Ok(_) => {
                let magic = (buf[0] as u32) | ((buf[1] as u32)<<8) | ((buf[2] as u32)<<16) | ((buf[3] as u32)<<24);
                if magic == 0 {
                    break;
                };
                assert_eq!(3652501241, magic);
            }
        }
        reader.read_exact(&mut buf);
        let size = (buf[0] as u32) | ((buf[1] as u32)<<8) | ((buf[2] as u32)<<16) | ((buf[3] as u32)<<24);
        //println!("Read size {:?}", size);
        println!("Block {:?}", block_number);
        read_block(&mut reader, size as u64, &mut block);
        block_number += 1;
    }
    block_number
}

fn read_block<R>(reader:R, size: u64, block: &mut Vec<u8>) where R: Read, {
    block.clear();
    let mut block_reader = reader.take(size);
    match block_reader.read_to_end(block) {
        Err(_) => println!("Error reading block"),
        Ok(len) => {
            let (tx_count, pos) = read_varint(&block, 80);
            println!("Number of transactions: {:?}", tx_count);
            let mut p = pos;
            for _ in 0..tx_count {
                let version_p = read_u32(&block, p);
                p = version_p.1;
                // Read number of inputs
                let num_inputs_p = read_varint(&block, p);
                let num_inputs = num_inputs_p.0;
                p = num_inputs_p.1;
                for _ in 0..num_inputs {
                    let is_coinbase = block[p..p+32] == [0u8;32];
                    p += 32; // Skip prevout_hash
                    p += 4; // Skip prevous_n
                    let script_sig_len_p = read_varint(&block, p);
                    let script_sig_len = script_sig_len_p.0;
                    p = script_sig_len_p.1;
                    if !is_coinbase {
                        let script_sig: &[u8] = &block[p..p+(script_sig_len as usize)];
                        let decoded_script_sig = decode_script(script_sig);
                        //public_key_from_script(decoded_script_sig);
                    }
                    p = script_sig_len_p.1;
                    p += script_sig_len as usize; // Skip script_sig for now
                    p += 4; // Skip sequence
                }
                let num_outputs_p = read_varint(&block, p);
                let num_outputs = num_outputs_p.0;
                p = num_outputs_p.1;
                for _ in 0..num_outputs {
                    let value_p = read_u64(&block, p);
                    p = value_p.1;
                    let script_pub_key_len_p = read_varint(&block, p);
                    let script_pub_key_len = script_pub_key_len_p.0;
                    p = script_pub_key_len_p.1;
                    p += script_pub_key_len as usize; // Skip script_pub_key for now
                }
                p += 4; // Skip locktime
            }
            assert_eq!(size as usize, p);
        },
    }
}

fn read_u16(slice: &[u8], pos: usize) -> (u16, usize) {
    ((slice[pos] as u16) | ((slice[pos+1] as u16)<<8), pos+2)
}
fn read_u32(slice: &[u8], pos: usize) -> (u32, usize) {
    ((slice[pos] as u32) | ((slice[pos+1] as u32)<<8) | ((slice[pos+2] as u32)<<16) | ((slice[pos+3] as u32)<<24), pos+4)
}

fn read_u64(slice: &[u8], pos: usize) -> (u64, usize) {
    ((slice[pos] as u64) | ((slice[pos+1] as u64)<<8) | ((slice[pos+2] as u64)<<16) | ((slice[pos+3] as u64)<<24) |
        ((slice[pos+4] as u64)<<32) | ((slice[pos+5] as u64)<<40) | ((slice[pos+6] as u64)<<48) | ((slice[pos+7] as u64)<<56), pos+8)
}

fn read_varint(slice: &[u8], pos: usize) -> (u64, usize) {
    match slice[pos] {
        0xFD => ((slice[pos+1] as u64) | ((slice[pos+2] as u64)<<8), pos+3),
        0xFE => ((slice[pos+1] as u64) | ((slice[pos+2] as u64)<<8) | ((slice[pos+3] as u64)<<16) | ((slice[pos+4] as u64)<<24), pos+5),
        0xFF => ((slice[pos+1] as u64) | ((slice[pos+2] as u64)<<8) | ((slice[pos+3] as u64)<<16) | ((slice[pos+4] as u64)<<24) |
                 ((slice[pos+5] as u64)<<32) | ((slice[pos+6] as u64)<<40) | ((slice[pos+7] as u64)<<48) | ((slice[pos+8] as u64)<<56), pos+9),
        _ => (slice[pos] as u64, pos+1),
    }
}

enum Opcode {
    Op0 = 0x00,
    OpPushdata1 = 0x4C, OpPushdata2, OpPushdata4,
    Op1Negate,
    OpReserved,
    Op1, Op2, Op3, Op4, Op5, Op6, Op7, Op8, Op9, Op10, Op11, Op12, Op13, Op14, Op15, Op16,
    OpNop, OpVer, OpIf, OpNotif, OpVerif, OpVerNotIf, OpElse, OpEndif, OpVerify,
    OpReturn, OpTotalStack, OpFromaltstack, Op2Drop, Op2Dup, Op3Dup, Op2Over, Op2Rot, Op2Swap,
    OpIfdup, OpDepth, OpDrop, OpDup, OpNip, OpOver, OpPick, OpRoll, OpRot,
    OpSwap, OpTuck, OpCat, OpSubstr, OpLeft, OpRight, OpSize, OpInvert, OpAnd,
    OpOr, OpXor, OpEqual, OpEqualverify, OpReserved1, OpReserved2, Op1Add, Op1Sub, Op2Mul,
    Op2Div, OpNegate, OpAbs, OpNot, Op0NotEqual, OpAdd, OpSub, OpMul, OpDiv,
    OpMod, OpLshift, OpRshift, OpBooland, OpBoolor,
    OpNumequal, OpNumequalverify, OpNumnotequal, OpLessthan,
    OpGreaterthan, OpLessthanorequal, OpGreaterthanorequal, OpMin, OpMax,
    OpWithin, OpRipemd160, OpSha1, OpSha256, OpHash160,
    OpHash256, OpCodeseparator, OpChecksig, OpChecksigverify, OpCheckmultisig,
    OpCheckmultisigverify,
    OpNop1, OpNop2, OpNop3, OpNop4, OpNop5, OpNop6, OpNop7, OpNop8, OpNop9, OpNop10,
    OpInvalidopcode = 0xFF,
}

fn decode_script(slice: &[u8]) -> Vec<(u8, Option<&[u8]>)> {
    let mut script: Vec<(u8, Option<&[u8]>)> = vec![];
    let mut pos: usize = 0;
    while pos < slice.len() {
        let opcode = slice[pos];
        pos += 1;
        if opcode <= Opcode::OpPushdata4 as u8 {
            let (n_size, new_pos) =
                if opcode == Opcode::OpPushdata1 as u8 {
                    (slice[pos] as usize, pos + 1)
                } else if opcode == Opcode::OpPushdata2 as u8 {
                    let r = read_u16(slice, pos);
                    (r.0 as usize, r.1)
                } else if opcode == Opcode::OpPushdata4 as u8 {
                    let r = read_u32(slice, pos);
                    (r.0 as usize, r.1)
                } else {
                    (opcode as usize, pos)
                };
            pos = new_pos;
            script.push((opcode, Some(&slice[pos..pos+n_size])));
            pos += n_size;
        } else {
            script.push((opcode, None));
        }
    }
    script
}

fn public_key_from_script(decoded_script: Vec<(u8, Option<&[u8]>)>) -> Option<[u8;20]>{
    if decoded_script.len() == 0 {
        None
    } else if decoded_script[0].0 == Opcode::Op0 as u8 {
        // Beginning of a multisignature spend ?
        match decoded_script[decoded_script.len()-1].1 {
            None => None,
            Some(sub_script) => {
                let decoded_sub_script = decode_script(sub_script);
                let mut sha256 = crypto::sha2::Sha256::new();
                sha256.input(sub_script);
                let mut buffer32b: [u8;32] = [0;32];
                sha256.result(&mut buffer32b);
                let mut ripemd160 = crypto::ripemd160::Ripemd160::new();
                ripemd160.input(&buffer32b);
                let mut buffer20b: [u8;20] = [0;20];
                ripemd160.result(&mut buffer20b);
                None
            }
        }
    } else if decoded_script[0].0 <= Opcode::OpPushdata4 as u8 {
        None
    } else {
        None
    }
}
