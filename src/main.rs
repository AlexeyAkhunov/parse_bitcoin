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
                                            action_input_output(&id, &block[p..p+(script_sig_len as usize)], prevout_script.as_slice(), prevout_n);
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
                                                action_input_output(&id, input_script, output.as_slice(), i);
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

enum OutputType {
    PayToAddress,
    PayToPublicKey,
    PayToCompactPublicKey,
    PayToHash,
    PayToScriptHash,
    Multisig1of1,
    Multisig1of2,
    Multisig1of3,
    Multisig2of2,
    Multisig2of3,
    Multisig16of16,
    Unclassified,
    Strange1,
    Strange2,
    Strange3,
    Strange4,
    Strange5,
    Strange6,
    Strange7,
    Strange8,
    Strange9,
    Strange10,
    Strange11,
    Empty,
    OpDup,
}

fn classify_output(tx_id: &[u8], output: &[u8], output_idx: usize) -> OutputType {
    match decode_script(output) {
        Err(why) => {
            println!("Could not decode output in txid: {:?}, error: {:?}", print_32bytes(tx_id), why)
        },
        Ok(decoded_output) => {
            if decoded_output.len() == 0 {
                return OutputType::Empty;
            } else {
                let op0 = decoded_output[0].0;
                if op0 == Opcode::OpDup as u8 {
                    if decoded_output.len() == 1 {
                        return OutputType::OpDup;
                    } else {
                        let op1 = decoded_output[1].0;
                        if op1 == Opcode::OpHash160 as u8 {
                            if decoded_output.len() > 2 && decoded_output[2].0 == 20u8 {
                                if decoded_output.len() > 3 && decoded_output[3].0 == Opcode::OpEqualverify as u8 {
                                    if decoded_output.len() == 5 && decoded_output[4].0 == Opcode::OpChecksig as u8 {
                                        return OutputType::PayToAddress;
                                    }
                                }
                            }
                        } else if op1 == Opcode::Op0 as u8 {
                            if decoded_output.len() > 2 && decoded_output[2].0 == Opcode::OpLessthan as u8 {
                                if decoded_output.len() > 3 && decoded_output[3].0 == Opcode::OpVerify as u8 {
                                    if decoded_output.len() > 4 && decoded_output[4].0 == Opcode::OpAbs as u8 {
                                        if decoded_output.len() > 5 && decoded_output[5].0 == Opcode::Op1 as u8 {
                                            if decoded_output.len() > 6 && decoded_output[6].0 == Opcode::Op16 as u8 {
                                                if decoded_output.len() > 7 && decoded_output[7].0 == Opcode::OpWithin as u8 {
                                                    if decoded_output.len() > 8 && decoded_output[8].0 == Opcode::OpTotalStack as u8 {
                                                        if decoded_output.len() > 9 && decoded_output[9].0 == 33u8 {
                                                            if decoded_output.len() > 10 && decoded_output[10].0 == Opcode::OpChecksigverify as u8 {
                                                                if decoded_output.len() == 12 && decoded_output[11].0 == Opcode::OpFromaltstack as u8 {
                                                                    return OutputType::Strange7;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }                            
                        }
                    }
                } else if op0 == 65u8 {
                    if decoded_output.len() == 2 && decoded_output[1].0 == Opcode::OpChecksig as u8 {
                        return OutputType::PayToPublicKey;
                    }
                } else if op0 == 33u8 {
                    if decoded_output.len() > 1 {
                        let op1 = decoded_output[1].0;
                        if decoded_output.len() == 2 && op1 == Opcode::OpChecksig as u8 {
                            return OutputType::PayToCompactPublicKey;
                        } else if op1 == Opcode::OpSwap as u8 {
                            if decoded_output.len() > 2 && decoded_output[2].0 == Opcode::Op1Add as u8 {
                                if decoded_output.len() == 4 && decoded_output[3].0 == Opcode::OpCheckmultisig as u8 {
                                    return OutputType::Strange6;
                                }
                            }
                        } else if op1 == Opcode::OpChecksig as u8 {
                            if decoded_output.len() > 2 && decoded_output[2].0 == Opcode::OpSwap as u8 {
                                if decoded_output.len() > 3 && decoded_output[3].0 == 33u8 {
                                    if decoded_output.len() > 4 && decoded_output[4].0 == Opcode::OpChecksig as u8 {
                                        if decoded_output.len() > 5 && decoded_output[5].0 == Opcode::OpSwap as u8 {
                                            if decoded_output.len() > 6 && decoded_output[6].0 == Opcode::Op3 as u8 {
                                                if decoded_output.len() > 7 && decoded_output[7].0 == Opcode::OpPick as u8 {
                                                    if decoded_output.len() > 8 && decoded_output[8].0 == Opcode::OpSha256 as u8 {
                                                        if decoded_output.len() > 9 && decoded_output[9].0 == 32u8 {
                                                            if decoded_output.len() > 10 && decoded_output[10].0 == Opcode::OpEqual as u8 {
                                                                if decoded_output.len() > 11 && decoded_output[11].0 == Opcode::Op3 as u8 {
                                                                    if decoded_output.len() > 12 && decoded_output[12].0 == Opcode::OpPick as u8 {
                                                                        if decoded_output.len() > 13 && decoded_output[13].0 == Opcode::OpSha256 as u8 {
                                                                            if decoded_output.len() > 14 && decoded_output[14].0 == 32u8 {
                                                                                if decoded_output.len() > 15 && decoded_output[15].0 == Opcode::OpEqual as u8 {
                                                                                    if decoded_output.len() == 47 && decoded_output[16].0 == Opcode::OpBooland as u8 &&
                                                                                    decoded_output[17].0 == Opcode::Op4 as u8 &&
                                                                                    decoded_output[18].0 == Opcode::OpPick as u8 &&
                                                                                    decoded_output[19].0 == Opcode::OpSize as u8 &&
                                                                                    decoded_output[20].0 == Opcode::OpNip as u8 &&
                                                                                    decoded_output[21].0 == 1u8 &&
                                                                                    decoded_output[22].0 == 1u8 &&
                                                                                    decoded_output[23].0 == Opcode::OpWithin as u8 &&
                                                                                    decoded_output[24].0 == Opcode::OpBooland as u8 &&
                                                                                    decoded_output[25].0 == Opcode::Op3 as u8 &&
                                                                                    decoded_output[26].0 == Opcode::OpPick as u8 &&
                                                                                    decoded_output[27].0 == Opcode::OpSize as u8 &&
                                                                                    decoded_output[28].0 == Opcode::OpNip as u8 &&
                                                                                    decoded_output[29].0 == 1u8 &&
                                                                                    decoded_output[30].0 == 1u8 &&
                                                                                    decoded_output[31].0 == Opcode::OpWithin as u8 &&
                                                                                    decoded_output[32].0 == Opcode::OpBooland as u8 &&
                                                                                    decoded_output[33].0 == Opcode::OpIf as u8 &&
                                                                                    decoded_output[34].0 == Opcode::Op3 as u8 &&
                                                                                    decoded_output[35].0 == Opcode::OpPick as u8 &&
                                                                                    decoded_output[36].0 == Opcode::OpSize as u8 &&
                                                                                    decoded_output[37].0 == Opcode::OpNip as u8 &&
                                                                                    decoded_output[38].0 == Opcode::Op3 as u8 &&
                                                                                    decoded_output[39].0 == Opcode::OpPick as u8 &&
                                                                                    decoded_output[40].0 == Opcode::OpSize as u8 &&
                                                                                    decoded_output[41].0 == Opcode::OpNip as u8 &&
                                                                                    decoded_output[42].0 == Opcode::OpEqual as u8 &&
                                                                                    decoded_output[43].0 == Opcode::OpPick as u8 &&
                                                                                    decoded_output[44].0 == Opcode::OpElse as u8 &&
                                                                                    decoded_output[45].0 == Opcode::OpBooland as u8 &&
                                                                                    decoded_output[46].0 == Opcode::OpEndif as u8 {
                                                                                        return OutputType::Strange9;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if op0 == 20u8 {
                    if decoded_output.len() > 1 && decoded_output[1].0 == Opcode::OpNop2 as u8 {
                        if decoded_output.len() == 3 && decoded_output[2].0 == Opcode::OpDrop as u8 {
                            return OutputType::Strange1;
                        }
                    }
                } else if op0 == 8u8 {
                    if decoded_output.len() > 1 && decoded_output[1].0 == Opcode::OpDrop as u8 {
                        if decoded_output.len() > 2 && decoded_output[2].0 == Opcode::OpSha256 as u8 {
                            if decoded_output.len() > 3 && decoded_output[3].0 == 32u8 {
                                if decoded_output.len() == 5 && decoded_output[4].0 == Opcode::OpEqual as u8 {
                                    return OutputType::PayToHash;
                                }
                            }
                        }
                    }
                } else if op0 == 76u8 {
                     if decoded_output.len() > 1 && decoded_output[1].0 == Opcode::OpDrop as u8 {
                        if decoded_output.len() > 2 && decoded_output[2].0 == Opcode::OpDup as u8 {
                            if decoded_output.len() > 3 && decoded_output[3].0 == Opcode::OpHash160 as u8 {
                                if decoded_output.len() > 4 && decoded_output[4].0 == 20u8 {
                                    if decoded_output.len() > 5 && decoded_output[5].0 == Opcode::OpEqualverify as u8 {
                                        if decoded_output.len() == 7 && decoded_output[6].0 == Opcode::OpChecksig as u8 {
                                            return OutputType::Strange8;
                                        }
                                    }
                                }
                            }
                        }
                   }
                } else if op0 == Opcode::Op2 as u8 {
                    if decoded_output.len() > 1 && (decoded_output[1].0 == 33u8 || decoded_output[1].0 == 65u8) {
                        if decoded_output.len() > 2 && (decoded_output[2].0 == 33u8 || decoded_output[2].0 == 65u8) {
                            if decoded_output.len() > 3 {
                                let op3 = decoded_output[3].0;
                                if op3 == 65u8 || op3 == 33u8 {
                                    if decoded_output.len() > 4 && decoded_output[4].0 == Opcode::Op3 as u8 {
                                        if decoded_output.len() == 6 && decoded_output[5].0 == Opcode::OpCheckmultisig as u8 {
                                            return OutputType::Multisig2of3;
                                        }
                                    }
                                } else if op3 == Opcode::Op2 as u8 {
                                    if decoded_output.len() == 5 && decoded_output[4].0 == Opcode::OpCheckmultisig as u8 {
                                        return OutputType::Multisig2of2;
                                    }
                                }
                            }
                        }
                    }
                } else if op0 == Opcode::OpMin as u8 {
                    if decoded_output.len() > 1 && decoded_output[1].0 == Opcode::Op3 as u8 {
                        if decoded_output.len() ==3 && decoded_output[2].0 == Opcode::OpEqual as u8 {
                            return OutputType::Strange2;
                        }
                    }
                } else if op0 == Opcode::OpHash160 as u8 {
                    if decoded_output.len() > 1 && decoded_output[1].0 == 20u8 {
                        if decoded_output.len() == 3 && decoded_output[2].0 == Opcode::OpEqual as u8 {
                            return OutputType::PayToScriptHash;
                        }
                    }
                } else if (op0 == 32u8 || op0 == 36u8) && decoded_output.len() == 1 {
                    return OutputType::Strange3;
                } else if op0 == Opcode::Op1 as u8 {
                    if decoded_output.len() > 1 {
                        let op1 = decoded_output[1].0;
                        if op1 == 33u8 || op1 == 65u8 || op1 == 76u8 || op1 == 52u8 {
                            if decoded_output.len() > 2 {
                                let op2 = decoded_output[2].0;
                                if op2 == 33u8 || op2 == 65u8  || op2 == 76u8 {
                                    if decoded_output.len() > 3 {
                                        let op3 = decoded_output[3].0;
                                        if op3 == Opcode::Op2 as u8 {
                                            if decoded_output.len() == 5 && decoded_output[4].0 == Opcode::OpCheckmultisig as u8 {
                                                return OutputType::Multisig1of2;
                                            }
                                        } else if op3 == 33u8 || op3 == 65u8 {
                                            if decoded_output.len() > 4 && decoded_output[4].0 == Opcode::Op3 as u8 {
                                                if decoded_output.len() == 6 && decoded_output[5].0 == Opcode::OpCheckmultisig as u8 {
                                                    return OutputType::Multisig1of3;
                                                }
                                            }
                                        }
                                    }
                                } else if op2 == Opcode::Op1 as u8 {
                                    if decoded_output.len() == 4 && decoded_output[3].0 == Opcode::OpCheckmultisig as u8 {
                                        return OutputType::Multisig1of1;
                                    }
                                }
                            }
                        }
                    }
                } else if op0 == Opcode::OpIf as u8 {
                    if decoded_output.len() > 1 && decoded_output[1].0 == Opcode::OpHash256 as u8 {
                        if decoded_output.len() > 2 && decoded_output[2].0 == 32u8 {
                            if decoded_output.len() > 3 && decoded_output[3].0 == Opcode::OpEqual as u8 {
                                if decoded_output.len() > 4 && decoded_output[4].0 == Opcode::OpElse as u8 {
                                    if decoded_output.len() > 5 && decoded_output[5].0 == Opcode::OpHash256 as u8 {
                                        if decoded_output.len() > 6 && decoded_output[6].0 == 32u8 {
                                            if decoded_output.len() > 7 && decoded_output[7].0 == Opcode::OpEqual as u8 {
                                                if decoded_output.len() == 9 && decoded_output[8].0 == Opcode::OpEndif as u8 {
                                                    return OutputType::Strange4;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if op0 == Opcode::OpDepth as u8 {
                    if decoded_output.len() > 1 && decoded_output[1].0 == Opcode::OpHash256 as u8 {
                        if decoded_output.len() > 2 && decoded_output[2].0 == Opcode::OpHash160 as u8 {
                            if decoded_output.len() > 3 && decoded_output[3].0 == Opcode::OpSha256 as u8 {
                                if decoded_output.len() > 4 && decoded_output[4].0 == Opcode::OpSha1 as u8 {
                                    if decoded_output.len() > 5 && decoded_output[5].0 == Opcode::OpRipemd160 as u8 {
                                        if decoded_output.len() == 7 && decoded_output[6].0 == Opcode::OpEqual as u8 {
                                            return OutputType::Strange5;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if op0 == Opcode::OpSize as u8 {
                    if decoded_output.len() == 57 &&
                    decoded_output[1].0 == Opcode::OpTuck as u8 && decoded_output[2].0 == 1u8 && decoded_output[3].0 == 1u8 &&
                    decoded_output[4].0 == Opcode::OpWithin as u8 && decoded_output[5].0 == Opcode::OpVerify as u8 && decoded_output[6].0 == Opcode::OpSha256 as u8 &&
                    decoded_output[7].0 == 32u8 && decoded_output[8].0 == Opcode::OpEqualverify as u8 && decoded_output[9].0 == Opcode::OpSwap as u8 &&
                    decoded_output[10].0 == Opcode::OpSize as u8 && decoded_output[11].0 == Opcode::OpTuck as u8 && decoded_output[12].0 == 1u8 &&
                    decoded_output[13].0 == 1u8 && decoded_output[14].0 == Opcode::OpWithin as u8 && decoded_output[15].0 == Opcode::OpVerify as u8 &&
                    decoded_output[16].0 == Opcode::OpSha256 as u8 && decoded_output[17].0 == 32u8 && decoded_output[18].0 == Opcode::OpEqualverify as u8 &&
                    decoded_output[19].0 == Opcode::OpRot as u8 && decoded_output[20].0 == Opcode::OpSize as u8 && decoded_output[21].0 == Opcode::OpTuck as u8 &&
                    decoded_output[22].0 == 1u8 && decoded_output[23].0 == 1u8 && decoded_output[24].0 == Opcode::OpWithin as u8 &&
                    decoded_output[25].0 == Opcode::OpVerify as u8 && decoded_output[26].0 == Opcode::OpSha256 as u8 && decoded_output[27].0 == 32u8 &&                  
                    decoded_output[28].0 == Opcode::OpEqualverify as u8 && decoded_output[29].0 == Opcode::OpAdd as u8 && decoded_output[30].0 == Opcode::OpAdd as u8 &&
                    decoded_output[31].0 == 1u8 as u8 && decoded_output[32].0 == Opcode::OpSub as u8 && decoded_output[33].0 == Opcode::OpDup as u8 &&
                    decoded_output[34].0 == Opcode::Op2 as u8 && decoded_output[35].0 == Opcode::OpGreaterthan as u8 && decoded_output[36].0 == Opcode::OpIf as u8 &&
                    decoded_output[37].0 == Opcode::Op3 as u8 && decoded_output[38].0 == Opcode::OpSub as u8 && decoded_output[39].0 == Opcode::OpEndif as u8 &&
                    decoded_output[40].0 == Opcode::OpDup as u8 && decoded_output[41].0 == Opcode::Op2 as u8 && decoded_output[42].0 == Opcode::OpGreaterthan as u8 &&
                    decoded_output[43].0 == Opcode::OpIf as u8 && decoded_output[44].0 == Opcode::Op3 as u8 && decoded_output[45].0 == Opcode::OpSub as u8 &&
                    decoded_output[46].0 == Opcode::OpEndif as u8 && decoded_output[47].0 == 65u8 && decoded_output[48].0 == 65u8 &&
                    decoded_output[49].0 == 65u8 && decoded_output[50].0 == Opcode::Op3 as u8 && decoded_output[51].0 == Opcode::OpRoll as u8 &&
                    decoded_output[52].0 == Opcode::OpRoll as u8 && decoded_output[53].0 == Opcode::Op3 as u8 && decoded_output[54].0 == Opcode::OpRoll as u8 &&
                    decoded_output[55].0 == Opcode::OpSwap as u8 && decoded_output[56].0 == Opcode::OpChecksigverify as u8
                    {
                        return OutputType::Strange10;
                    }
                } else if op0 == Opcode::Op2Dup as u8 {
                    if decoded_output.len() == 7 && 
                    decoded_output[1].0 == Opcode::OpAdd as u8 && decoded_output[2].0 == Opcode::Op8 as u8 && decoded_output[3].0 == Opcode::OpEqualverify as u8 &&
                    decoded_output[4].0 == Opcode::OpSub as u8 && decoded_output[5].0 == Opcode::Op2 as u8 && decoded_output[6].0 == Opcode::OpEqual as u8 {
                        return OutputType::Strange11;
                    }
                } else if op0 == Opcode::Op16 as u8 {
                    if decoded_output.len() == 19 &&
                    decoded_output[1].0 == 65u8 && decoded_output[2].0 == 65u8 && decoded_output[3].0 == 65u8 && decoded_output[4].0 == 65u8 &&
                    decoded_output[5].0 == 65u8 && decoded_output[6].0 == 65u8 && decoded_output[7].0 == 65u8 && decoded_output[8].0 == 65u8 &&
                    decoded_output[9].0 == 65u8 && decoded_output[10].0 == 65u8 && decoded_output[11].0 == 65u8 && decoded_output[12].0 == 65u8 &&
                    decoded_output[13].0 == 65u8 && decoded_output[14].0 == 65u8 && decoded_output[15].0 == 65u8 && decoded_output[16].0 == 65u8 &&
                    decoded_output[17].0 == Opcode::Op16 as u8 && decoded_output[18].0 == Opcode::OpCheckmultisig as u8 {
                        return OutputType::Multisig16of16;
                    }
                }
            }
            println!("Unclassified tx output {:?} {:?} len {:?}: {:?}", print_32bytes(tx_id), output_idx, decoded_output.len(), decoded_output);
        }
    }
    return OutputType::Unclassified;
}

fn action_input_output(tx_id: &[u8], input: &[u8], output: &[u8], output_idx: usize) {
    classify_output(tx_id, output, output_idx);
    let decoded_script_sig = decode_script(input);
    match decoded_script_sig {
        Err(why) => {
            println!("txid: {:?}, error: {:?}", print_32bytes(tx_id), why);
        },
        Ok(decoded) => {
            let addr = public_key_from_script(decoded);
            match addr {
                Some(addr_str) => {
                    //println!("{:?}, txid: {:?}", addr_str, print_32bytes(tx_id));
                },
                None => {}
            }
        }
    }
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
    buffer32b
}

fn print_32bytes(bytes: &[u8]) -> String {
    let mut s = String::new();
    for i in 0..bytes.len() {
        write!(&mut s, "{:02x}", bytes[bytes.len()-i-1]).unwrap();
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
