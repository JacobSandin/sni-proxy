//use std::io::{self, BufRead};

use std::io::{self, BufRead};

pub fn try_iterate_bytes(in_buf: Vec<u8>) {
    let buf = in_buf.clone();
    let buf = buf.as_slice();
    

    let mut cursor = io::Cursor::new(buf);
    let mut lines = String::new();


    let _num_bytes = cursor
        .read_line(&mut lines)
        .expect("reading from cursor won't fail");

        for l in cursor.lines() {
            error!("{}",l.unwrap());
        }

error!("===================================================================================================");
//     let mut work: Vec<u8> = Vec::new();
//     let mut headers_buf: Vec<u8> = Vec::new();
//     let mut body: Vec<u8> = Vec::new();
//     let mut nr_lf = 0;
//     for b in buf {
//         if nr_lf == 4 {
//             //error!("dubble linefeed");
//             if headers_buf.len() == 0 {
//                 headers_buf.append(&mut work.clone());
//                 work.clear();
//             }
//             nr_lf=0;
//         } else if headers_buf.len()== 0 {
//             match b {
//                 &b'\n' => {
//                     //error!("linefeed b: {}",b);
//                     nr_lf += 1;
//                 }
//                 &b'\r' => {
//                     //error!("linefeed2 b: {}",b);
//                     nr_lf += 1;
//                 }
//                 _ => {
//                     nr_lf = 0;
//                 }
//             }
//         }
//         work.push(*b);
//     }
//     body.append(&mut work);
// //    error!("Headers: \r\n{}", String::from_utf8_lossy(&headers_buf));
}
