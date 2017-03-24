use std::fs;
use std::result::Result;
use std::fs::File;
use std::fs::Metadata;
use std::io;
use std::io::{Read, BufReader, Seek, SeekFrom};
use std::option::Option;
use std::fmt::{Write, format};

extern crate crypto;
use crypto::digest::Digest;

extern crate rust_base58;

use rust_base58::{ToBase58, FromBase58};

use std::collections::HashMap;

extern crate bloomfilter;
use bloomfilter::Bloom;

fn main() {
    let mut out_map = HashMap::new();
    let mut in_map = HashMap::new();
    for prefix in 0..4 {
        match fs::read_dir("/Users/alexeyakhunov/Library/Application Support/Bitcoin/blocks") {
            Err(why) => println!("{:?}", why),
            Ok(dir_entries) => {
                let mut block_number: u32 = 0;
                for dir_entry in dir_entries {
                    block_number = parse_file(prefix, dir_entry, block_number, &mut in_map, &mut out_map);
                    if block_number > 1000000 {
                        break;
                    }
                }
            }
        }
    };
}

fn parse_file(prefix: u8, dir_entry: io::Result<fs::DirEntry>, initial_block: u32,
        in_map: &mut HashMap<[u8;32], Vec<Option<Vec<u8>>>>,
        out_map: &mut HashMap<[u8;32], Vec<Option<Vec<u8>>>>) -> u32 {
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
                        println!("Opened {:?}, prefix {:?}", filename, prefix);
                        let bn = read_blocks(prefix, &mut file, metadata.len(), initial_block, in_map, out_map);
                        println!("outputs: {:?}, inputs: {:?}", out_map.len(), in_map.len());
                        bn
                    },
                }
            } else {
                0
            }
        }
    }
}

fn read_blocks(prefix: u8, file: &mut File, filesize: u64, initial_block: u32,
        in_map: &mut HashMap<[u8;32], Vec<Option<Vec<u8>>>>,
        out_map: &mut HashMap<[u8;32], Vec<Option<Vec<u8>>>>) -> u32 {
    let mut reader = BufReader::new(file);
    let mut buf: [u8; 4] = [0u8; 4];
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
        //println!("Block {:?}", block_number);
        read_block(prefix, &mut reader, size as u64, in_map, out_map);
        block_number += 1;
    }
    block_number
}

fn read_block<R>(prefix: u8, reader: R, size: u64,
        in_map: &mut HashMap<[u8;32], Vec<Option<Vec<u8>>>>,
        out_map: &mut HashMap<[u8;32], Vec<Option<Vec<u8>>>>) where R: Read {
    let mut block: Vec<u8> = Vec::with_capacity(1024*1024);
    let mut block_reader = reader.take(size);
    match block_reader.read_to_end(&mut block) {
        Err(_) => println!("Error reading block"),
        Ok(len) => {
            let (tx_count, pos) = read_varint(&block, 80);
            //println!("Number of transactions: {:?}", tx_count);
            let mut p = pos;
            for _ in 0..tx_count {
                let tx_start = p;
                let version_p = read_u32(&block, p);
                p = version_p.1;
                // Read number of inputs
                let num_inputs_p = read_varint(&block, p);
                let num_inputs = num_inputs_p.0;
                p = num_inputs_p.1;
                for _ in 0..num_inputs {
                    let is_coinbase = block[p..p+32] == [0u8;32];
                    let prevout_hash_pos = p;
                    p += 32;
                    let prevout_n = read_u32(&block, p).0 as usize;
                    p += 4; // Skip prevous_n
                    let script_sig_len_p = read_varint(&block, p);
                    let script_sig_len = script_sig_len_p.0;
                    p = script_sig_len_p.1;
                    if !is_coinbase {
                        if (block[prevout_hash_pos] & 0x3) == prefix {
                            let id = copy_id(&block[prevout_hash_pos..prevout_hash_pos+32]);
                            let remove_from_map = match out_map.get_mut(&id) {
                                None => {
                                    let inputs: &mut Vec<Option<Vec<u8>>>;
                                    if !in_map.contains_key(&id) {
                                        in_map.insert(id, vec![]);
                                    }
                                    inputs = in_map.get_mut(&id).unwrap();
                                    // Add the input into the inputs vector
                                    while inputs.len() < prevout_n {
                                        inputs.push(None);
                                    };
                                    if inputs.len() == prevout_n {
                                        let cloned_script_sig = block[p..p+(script_sig_len as usize)].to_owned();
                                        inputs.push(Some(cloned_script_sig));
                                    };
                                    // Do not remove from map, because there is nothing to remove
                                    false
                                },
                                Some(prevout_scripts) => {
                                    let to_remove = match prevout_scripts[prevout_n] {
                                        None => false,
                                        Some(ref prevout_script) => {
                                            action_input_output(&id, &block[p..p+(script_sig_len as usize)], prevout_script.as_slice());
                                            true
                                        }
                                    };
                                    if to_remove {
                                        prevout_scripts[prevout_n] = None;
                                    };
                                    // If all elements are None, remove from the map
                                    prevout_scripts.iter().filter(|x| x.is_some()).count() == 0
                                }
                            };
                            if remove_from_map {
                                out_map.remove(&block[prevout_hash_pos..prevout_hash_pos+32]);
                            }
                        }
                    }
                    p += script_sig_len as usize; // Skip script_sig for now
                    p += 4; // Skip sequence
                }
                let num_outputs_p = read_varint(&block, p);
                let num_outputs = num_outputs_p.0;
                p = num_outputs_p.1;
                let mut utxos: Vec<Option<Vec<u8>>> = vec![];
                for _ in 0..num_outputs {
                    let value_p = read_u64(&block, p);
                    p = value_p.1;
                    let script_pub_key_len_p = read_varint(&block, p);
                    let script_pub_key_len = script_pub_key_len_p.0 as usize;
                    p = script_pub_key_len_p.1;
                    let cloned_script = block[p..p+script_pub_key_len].to_owned();
                    utxos.push(Some(cloned_script));
                    p += script_pub_key_len; // Skip script_pub_key for now
                }
                p += 4; // Skip locktime
                let id = tx_id(&block[tx_start..p]);
                if (id[0] & 0x3) == prefix {
                    // Go through UTXOs and check if we have matching inputs
                    let mut done_utxos = 0;
                    match in_map.remove(&id) {
                        None => {},
                        Some(inputs) => {
                            for i in 0..inputs.len() {
                                match inputs[i] {
                                    None => {},
                                    Some(ref input_script) => {
                                        let to_remove = match utxos[i] {
                                            None => false,
                                            Some(ref output) => {
                                                action_input_output(&id, input_script, output.as_slice());
                                                true
                                            }
                                        };
                                        if to_remove {
                                            utxos[i] = None;
                                            done_utxos += 1;
                                        }
                                    }
                                }
                            }
                        }
                    };
                    if done_utxos < utxos.len() {
                        out_map.insert(id, utxos);
                    }
                }
            }
            assert_eq!(size as usize, p);
        },
    }
}

fn action_input_output(tx_id: &[u8], input: &[u8], output: &[u8]) {
    let decoded_script_sig = decode_script(input);
    match decoded_script_sig {
        Err(why) => {
            println!("txid: {:?}, error: {:?}", print_32bytes(tx_id), why);
        },
        Ok(decoded) => {
            let addr = public_key_from_script(decoded);
            match addr {
                Some(addr_str) => {
                    //println!("{:?}", addr_str);
                },
                None => {}
            }
        }
    }
}

fn prevout_hash(prevout_hash_slice: &[u8]) {
    let mut a: [u8;32] = [0;32];
    a.clone_from_slice(prevout_hash_slice);
    a.reverse();
    println!("Prevout_hash: {}", print_32bytes(&a));    
}

fn copy_id(id_slice: &[u8]) -> [u8;32] {
    let mut buffer32b: [u8;32] = [0;32];
    for i in 0..32 {
        buffer32b[i] = id_slice[i];
    }
    buffer32b
}

fn tx_id(tx_slice: &[u8]) -> [u8;32] {
    let mut sha256 = crypto::sha2::Sha256::new();
    sha256.input(tx_slice);
    let mut buffer32b: [u8;32] = [0;32];
    sha256.result(&mut buffer32b);
    sha256.reset();
    sha256.input(&buffer32b[0..32]);
    sha256.result(&mut buffer32b);
    buffer32b.reverse();
    buffer32b.reverse();
    buffer32b
}

fn print_32bytes(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &byte in bytes {
        write!(&mut s, "{:02x}", byte).unwrap();
    };
    s   
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

fn decode_script(slice: &[u8]) -> Result<Vec<(u8, Option<&[u8]>)>,String> {
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
            if pos+n_size > slice.len() {
                return Err(format!("pos {:?}, n_size {:?}", pos, n_size));
            }
            script.push((opcode, Some(&slice[pos..pos+n_size])));
            pos += n_size;
        } else {
            script.push((opcode, None));
        }
    }
    Ok(script)
}

fn public_key_from_script(decoded_script: Vec<(u8, Option<&[u8]>)>) -> Option<String>{
    if decoded_script.len() == 0 {
        None
    } else if decoded_script[0].0 == Opcode::Op0 as u8 {
        // Beginning of a multisignature spend ?
        match decoded_script[decoded_script.len()-1].1 {
            None => None,
            Some(sub_script) => {
                //let decoded_sub_script = decode_script(sub_script);
                let mut sha256 = crypto::sha2::Sha256::new();
                sha256.input(sub_script);
                let mut buffer32b: [u8;32] = [0;32];
                sha256.result(&mut buffer32b);
                let mut ripemd160 = crypto::ripemd160::Ripemd160::new();
                ripemd160.input(&buffer32b);
                let mut buffer25b: [u8;25] = [0;25];
                buffer25b[0] = 5;
                ripemd160.result(&mut buffer25b[1..21]);
                sha256.reset();
                sha256.input(&buffer25b[0..21]);
                sha256.result(&mut buffer32b);
                sha256.reset();
                sha256.input(&buffer32b[0..32]);
                sha256.result(&mut buffer32b);
                buffer25b[21] = buffer32b[0];
                buffer25b[22] = buffer32b[1];
                buffer25b[23] = buffer32b[2];
                buffer25b[24] = buffer32b[3];
                let addr = buffer25b.to_base58();
                Some(addr)
            }
        }
    } else if decoded_script[0].0 <= Opcode::OpPushdata4 as u8 {
        None
    } else {
        None
    }
}
