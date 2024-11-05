use ipfixrw::information_elements::{get_default_formatter, Formatter};
use ipfixrw::{formatter, parse_ipfix_message};
use ipfixrw::parser::{DataRecord, DataRecordKey, DataRecordType, DataRecordValue, FieldSpecifier};
use ipfixrw::template_store::Template;
use ahash::{HashMap, HashMapExt};
use ipfix::{IpfixConsumer, IpfixPrinter};

use std::rc::Rc;
use std::cell::RefCell;

fn decode_field(field: FieldSpecifier) {
    if field.enterprise_number.is_none() {
        println!("Enterprise Number: None");
        return;
    }
    let en = field.enterprise_number.unwrap();
    let type_id_extension: bool = en & 0x8000_0000 != 0;
    let stats_id_extension: bool = en & 0x0000_8000 != 0;
    let type_id: u16 = ((en & 0x7FFF_0000) >> 16) as u16;
    let stats_id: u16 = (en & 0x0000_7FFF) as u16;
    println!("Enterprise Number: {:?}, Type ID Extension: {:?}, Stats ID Extension: {:?}, Type ID: {:?}, Stats ID: {:?}", en, type_id_extension, stats_id_extension, type_id, stats_id);
}

fn get_my_formatter() -> Formatter {
    formatter! {
        (0, 1) => ("octetDeltaCount", UnsignedInt) // unsigned64
    }
    // get_default_formatter()
}

fn main() {

    let template_bytes: [u8; 44] = [
        0x00, 0x0A, 0x00, 0x2C, // line 0
        0x00, 0x00, 0x00, 0x00, // line 1
        0x00, 0x00, 0x00, 0x01, // line 2
        0x00, 0x00, 0x00, 0x00, // line 3

        0x00, 0x02, 0x00, 0x1C, // line 4

        0x01, 0x00, 0x00, 0x03, // line 5 Template ID 256, 3 fields

        0x01, 0x45, 0x00, 0x08, // line 6 Field ID 325, 4 bytes

        0x80, 0x01, 0x00, 0x08, // line 7 Field ID 128, 8 bytes
        0x00, 0x01, 0x00, 0x02, // line 8 Enterprise Number 1, Field ID 1

        0x80, 0x02, 0x00, 0x08, // line 9 Field ID 129, 8 bytes
        0x80, 0x03, 0x80, 0x04, // line 10 Enterprise Number 128, Field ID 2
    ];
    let template = Box::new(template_bytes);

    // contains data sets for templates 999, 500, 999
    let data_bytes: [u8; 144] = [
        0x00, 0x0A, 0x00, 0x48, // line 0
        0x00, 0x00, 0x00, 0x00, // line 1
        0x00, 0x00, 0x00, 0x02, // line 2
        0x00, 0x00, 0x00, 0x00, // line 3

        0x01, 0x00, 0x00, 0x1C, // line 4

        0x00, 0x00, 0x00, 0x00, // line 5
        0x00, 0x00, 0x00, 0x01, // line 5
        0x00, 0x00, 0x00, 0x00, // line 7
        0x00, 0x00, 0x00, 0x01, // line 8
        0x00, 0x00, 0x00, 0x00, // line 9
        0x00, 0x00, 0x00, 0x01, // line 10

        0x01, 0x00, 0x00, 0x1C, // line 11

        0x00, 0x00, 0x00, 0x00, // line 12
        0x00, 0x00, 0x00, 0x02, // line 12
        0x00, 0x00, 0x00, 0x00, // line 13
        0x00, 0x00, 0x00, 0x02, // line 14
        0x00, 0x00, 0x00, 0x00, // line 15
        0x00, 0x00, 0x00, 0x03, // line 16

        0x00, 0x0A, 0x00, 0x48, // line 0
        0x00, 0x00, 0x00, 0x00, // line 1
        0x00, 0x00, 0x00, 0x02, // line 2
        0x00, 0x00, 0x00, 0x00, // line 3

        0x01, 0x00, 0x00, 0x1C, // line 4

        0x00, 0x00, 0x00, 0x00, // line 5
        0x00, 0x00, 0x00, 0x01, // line 5
        0x00, 0x00, 0x00, 0x00, // line 7
        0x00, 0x00, 0x00, 0x01, // line 8
        0x00, 0x00, 0x00, 0x00, // line 9
        0x00, 0x00, 0x00, 0x04, // line 10

        0x01, 0x00, 0x00, 0x1C, // line 11

        0x00, 0x00, 0x00, 0x00, // line 12
        0x00, 0x00, 0x00, 0x02, // line 12
        0x00, 0x00, 0x00, 0x00, // line 13
        0x00, 0x00, 0x00, 0x02, // line 14
        0x00, 0x00, 0x00, 0x00, // line 15
        0x00, 0x00, 0x00, 0x07, // line 16
    ];
    // let data = Box::new(&data_bytes[0 .. ]);

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_my_formatter());
    let msg = parse_ipfix_message(&template_bytes, templates.clone(), formatter.clone()).unwrap();
    println!("{:?}", msg);


    let mut read_size: usize = 0;
    while read_size < data_bytes.len() {
        let mut len = ipfix::get_message_length(&data_bytes[read_size ..]).unwrap();
        let data = &data_bytes[read_size .. read_size + len as usize];
        let data_message = parse_ipfix_message(&data, templates.clone(), formatter.clone()).unwrap();
        let datarecords: Vec<&DataRecord> = data_message.iter_data_records().collect();
        for record in datarecords {
            // for (key, val) in record.values.iter() {
            //     match key {
            //         DataRecordKey::Str(s) => println!("{}: {:?}", s, val),
            //         DataRecordKey::Unrecognized(k) => decode_field(k.clone()),
            //         _ => println!("Unrecognized"),
            //     }
            // }
            println!("{:?}", record);
        }
        read_size += len as usize;
    }


}
