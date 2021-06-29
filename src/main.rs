use rocksdb::{DB, Options, IteratorMode, ColumnFamilyDescriptor};
use clap::{Arg, App};
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{Read, BufReader};
use std::fmt::Error;
use std::convert::TryInto;

struct AOFHeader {
    op_code: u8,
    head_length: u64,
    body_length: u64
}

struct AOFMessage {
    header: AOFHeader,
    args : Vec<String>
}

struct AOF {

}

fn read_ne_u64(input: &mut &[u8]) -> u64 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u64>());
    *input = rest;
    u64::from_ne_bytes(int_bytes.try_into().unwrap())
}

fn read_ne_u8(input: &mut &[u8]) -> u8 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u8>());
    *input = rest;
    u8::from_ne_bytes(int_bytes.try_into().unwrap())
}

impl AOF {
    fn load<T: Read>(reader: &mut T) {
        let mut load_part = |size| {
            let mut buf = Vec::with_capacity(size);
            let mut part_reader = reader.take(size as u64);
            part_reader.read_to_end(&mut buf).unwrap();

            buf
        };

        let header = AOFHeader {
            op_code: read_ne_u8(&mut &*load_part(1)),
            head_length: read_ne_u64(&mut &*load_part(8)),
            body_length: read_ne_u64(&mut &*load_part(8)),
        };

        println!("op code: {}, header length: {}, body length: {}", &header.op_code, &header.head_length, &header.body_length);
        // take the header and body
        let key = String::from_utf8(load_part(header.head_length as usize)).unwrap();
        let value = String::from_utf8(load_part(header.body_length as usize)).unwrap();

        println!("[{}] {} -> {}", &header.op_code, &key, &value);

        // next one
    }
}

fn load_aof(aof_path: String) -> bool {
    if !Path::new(aof_path.as_str()).exists() {
        return false;
    }

    // parse the aof file;
    let mut f = OpenOptions::new().read(true).open(&aof_path).unwrap();
    let mut reader = BufReader::new(f);
    AOF::load(&mut reader);
    return true;
}

fn load_rocksdb() {
    let matches = App::new("osquery rocksdb checker")
        .version("1.0")
        .author("zouxiaoliang")
        .about("Does awesome things")
        .arg(Arg::new("dbpath")
            .short('p')
            .long("dbpath")
            .value_name("rocksdb path")
            .about("rocksdb path")
            .takes_value(true)
            .required(true)
            .default_value("/Users/zouxiaoliang/workspace/tmp/hoohoolab/osquery.db/")
        ).get_matches();

    let mut db_path = "/Users/zouxiaoliang/workspace/tmp/hoohoolab/osquery.db/";

    if let Some(path) = matches.value_of("dbpath") {
        db_path = path;
    }
    println!("rocks db path: {}", db_path);
    if !Path::new(db_path).exists() {
        println!("Not such rocksDB path {}", db_path);
        return
    }

    let mut db_options = Options::default();
    db_options.create_if_missing(true);
    db_options.create_missing_column_families(true);
    db_options.set_log_file_time_to_roll(0);
    db_options.set_keep_log_file_num(10);
    db_options.set_max_log_file_size(1024* 1024);
    db_options.set_max_open_files(128);
    db_options.set_stats_dump_period_sec(0);
    db_options.set_max_manifest_file_size(1024*500);

    db_options.set_compression_type(rocksdb::DBCompressionType::None);
    db_options.set_compaction_style(rocksdb::DBCompactionStyle::Level);
    db_options.set_arena_block_size(4*1024);
    db_options.set_write_buffer_size(4 * 1024 * 256);
    db_options.set_max_write_buffer_number(16);
    db_options.set_min_write_buffer_number_to_merge(4);
    // db_options.set_max_background_flushes(4);

    // column_families
    let default_column_family_name = ColumnFamilyDescriptor::new("default", db_options.clone());
    let mut column_family = Vec::new();
    column_family.push(default_column_family_name);
    let domains = ["configurations", "queries", "events", "carves", "logs"];
    for d in domains.iter() {
        column_family.push(ColumnFamilyDescriptor::new(*d, db_options.clone()))
    }

    {
        let db = DB::open_cf_descriptors(&db_options, db_path, column_family).unwrap();

        {
            // 读取跟路径数据
            let iter = db.iterator(IteratorMode::Start);
            for (key, value) in iter {
                // println!("Saw {:?} -> {:?}", key, value);
                let key: String = String::from_utf8(key.to_vec()).unwrap();
                let value: String = String::from_utf8(value.to_vec()).unwrap();

                println!("Saw {} -> {}", key, value);
            }
        }

        {
            // 读取列族信息
            for name in domains.iter() {
                let cf_handle = db.cf_handle(name);
                let cf_handle = cf_handle.unwrap();
                let iter = db.iterator_cf(cf_handle, IteratorMode::Start);
                for (key, value) in iter {
                    let key: String = String::from_utf8(key.to_vec()).unwrap();
                    let value: String = String::from_utf8(value.to_vec()).unwrap();

                    println!("Column family Saw {} -> {}", key, value);
                }
            }
        }
    }
    // 如果需要清空数据库，则打开注释
    // let _ = DB::destroy(&Options::default(), db_path);
}
fn main() {
    println!("Hello, world!");
    let aof_path = String::from("/Users/zouxiaoliang/workspace/cpp-build-dir/build-osquery-Debug/osquery/tiny.aof");
    load_aof(aof_path);
}
