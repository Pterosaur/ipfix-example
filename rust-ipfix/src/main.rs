use ipfix::{IpfixConsumer, IpfixPrinter};
use std::fs::File;
use std::io::prelude::*;

fn main() {

    let template_bytes: [u8; 44] = [
        0x00, 0x0A, 0x00, 0x2C, // line 0
        0x00, 0x00, 0x00, 0x00, // line 1
        0x00, 0x00, 0x00, 0x01, // line 2
        0x00, 0x00, 0x00, 0x00, // line 3

        0x00, 0x02, 0x00, 0x1C, // line 4

        0x01, 0x00, 0x00, 0x03, // line 5 Template ID 256, 3 fields

        0x01, 0x45, 0x00, 0x04, // line 6 Field ID 325, 4 bytes

        0x80, 0x01, 0x00, 0x08, // line 7 Field ID 128, 8 bytes
        0x00, 0x01, 0x00, 0x01, // line 8 Enterprise Number 1, Field ID 1

        0x80, 0x02, 0x00, 0x08, // line 9 Field ID 129, 8 bytes
        0x80, 0x02, 0x80, 0x02, // line 10 Enterprise Number 128, Field ID 2
    ];
    let template = Box::new(template_bytes);

    // contains data sets for templates 999, 500, 999
    let data_bytes: [u8; 128] = [
        0x00, 0x0A, 0x00, 0x40, // line 0
        0x00, 0x00, 0x00, 0x00, // line 1
        0x00, 0x00, 0x00, 0x02, // line 2
        0x00, 0x00, 0x00, 0x00, // line 3

        0x01, 0x00, 0x00, 0x18, // line 4

        0x00, 0x00, 0x00, 0x01, // line 5
        0x00, 0x00, 0x00, 0x00, // line 7
        0x00, 0x00, 0x00, 0x01, // line 8
        0x00, 0x00, 0x00, 0x00, // line 9
        0x00, 0x00, 0x00, 0x01, // line 10

        0x01, 0x00, 0x00, 0x18, // line 11

        0x00, 0x00, 0x00, 0x02, // line 12
        0x00, 0x00, 0x00, 0x00, // line 13
        0x00, 0x00, 0x00, 0x02, // line 14
        0x00, 0x00, 0x00, 0x00, // line 15
        0x00, 0x00, 0x00, 0x03, // line 16

        0x00, 0x0A, 0x00, 0x40, // line 0
        0x00, 0x00, 0x00, 0x00, // line 1
        0x00, 0x00, 0x00, 0x02, // line 2
        0x00, 0x00, 0x00, 0x00, // line 3

        0x01, 0x00, 0x00, 0x18, // line 4

        0x00, 0x00, 0x00, 0x01, // line 5
        0x00, 0x00, 0x00, 0x00, // line 7
        0x00, 0x00, 0x00, 0x01, // line 8
        0x00, 0x00, 0x00, 0x00, // line 9
        0x00, 0x00, 0x00, 0x04, // line 10

        0x01, 0x00, 0x00, 0x18, // line 11

        0x00, 0x00, 0x00, 0x02, // line 12
        0x00, 0x00, 0x00, 0x00, // line 13
        0x00, 0x00, 0x00, 0x02, // line 14
        0x00, 0x00, 0x00, 0x00, // line 15
        0x00, 0x00, 0x00, 0x07, // line 16
    ];
    let data = Box::new(&data_bytes[64 .. ]);

    let mut parser = IpfixConsumer::new();

    let printer = IpfixPrinter::new();

    assert!(parser.parse_message(&*template).is_ok());

    if let Ok(datarecords) = parser.parse_message(&*data) {
        let mut test_string = String::new();
        for datarecord in datarecords {
            let flows = printer.print_json(datarecord);
            for flow in flows {
                test_string += &flow;
            }
        }

        println!("{}", test_string);
    }

}
