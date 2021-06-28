use rocksdb::{DB, Options, IteratorMode, ColumnFamilyDescriptor};
use clap::{Arg, App};
use std::path::Path;

fn main() {
    println!("Hello, world!");
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
