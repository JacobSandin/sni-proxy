use fs::create_dir_all;
use header::HeaderMap;
use reqwest::{header, Url};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
};

pub struct CacheIterator {}

impl CacheIterator {
    pub fn find_host_dirs() {
        let file_dir = dotenv::var("CACHE_PATH").expect("Expected CACHE_PATH in .env file!");

        for entry in fs::read_dir(file_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let host = path.file_name().unwrap();
            let host = host.to_str().unwrap();
            println!("Name: {}", &host);
            CacheIterator::search_file_for_path(&host).unwrap();
        }
    }

    fn sanitize_file_name(file_name: String) -> String {
        file_name
            .replace("//", "/")
            .replace("\\/", "/")
            .replace("&", "!")
            .replace("?", "!")
            .replace("\\\\", "/")
    }

    fn search_file_for_path(host_name: &str) -> std::io::Result<bool> {
        let file_name1 = dotenv::var("CACHE_PATH").expect("Expected CACHE_PATH in .env file!");
        let file_name = format!(
            "{}/{}/{}",
            &file_name1, &host_name, "paths_to_cache_static.txt"
        );

        let mut static_file = false;
        let file_name = if std::path::Path::new(&file_name).exists() {
            static_file = true;
            file_name
        } else {
            format!("{}/{}/{}", &file_name1, &host_name, "paths_to_cache.txt")
        };

        let file_name = CacheIterator::sanitize_file_name(file_name);
        debug!("file_name: {:?}", &file_name);

        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(file_name)
            .unwrap();

        let reader = BufReader::new(f);

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .build()
            .unwrap();

        let mut cookie = String::new();

        for line in reader.lines() {
            let l = line?;
            info!("Line in paths file: {} Host: {}", l, host_name);
            if !l.is_empty() {
                if static_file {
                    if l.starts_with('#') || l.starts_with(';') {
                        //Do nothing its a comment
                    } else if l.starts_with("IGNORE_HOST") {
                        return Ok(false);
                    } else if l.starts_with("COOKIE=") {
                        cookie = String::from(&l[7..]);
                        error!("Cookie: {}", cookie);
                    //panic!("");
                    } else {
                        CacheIterator::http_get_file(&client, host_name, &l, &cookie);
                    }
                } else {
                    CacheIterator::http_get_file(&client, host_name, &l, "");
                }
                //error!("{} ", l);
            }
        }
        Ok(false)
    }

    fn http_get_file(client: &reqwest::blocking::Client, host: &str, path: &str, cookie: &str) {
        info!("Calling {}", &path);

        let url = format!("{}", &path);
        let url: Url = url.parse().unwrap();
        debug!("Url: {:?}", url);

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_str(&host).unwrap());
        headers.append(
            header::COOKIE,
            header::HeaderValue::from_str(cookie).unwrap(),
        );

        let resp = match client.get(url.clone()).headers(headers).send() {
            Ok(a) => a,
            Err(e) => {
                error!("Error GET: \r\n{:?}", e);
                return;
            }
        };
        let req = client
            .request(reqwest::Method::GET, url.clone())
            .header(header::HOST, header::HeaderValue::from_str(&host).unwrap())
            .build()
            .unwrap();

        error!("{:#?}", &resp);


        let file_name = CacheIterator::get_file_name(host, req.url().path());
        let file_name = CacheIterator::sanitize_file_name(file_name);
        let file_path = std::path::Path::new(&file_name);
        let file_path = file_path.parent().unwrap();

        debug!("file_path: {:?}", &file_path);
        debug!("file_name: {:?}", &file_name);
        match create_dir_all(&file_path) {
            Ok(_) => (),
            Err(_) => {
                return;
            }
        }
        let mut file = match std::fs::File::create(&file_name) {
            Ok(a) => a,
            Err(e) => {
                error!("Error creating file: {}\r\n{:?}", file_name, e);
                return;
            }
        };

        //error!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let mut head = String::new();
        head.push_str("HTTP/1.1 200 OK\r\n");
        head.push_str("Server: SNI-PROXY-CACHE/0.0.1\r\n");
        for (h, v) in resp.headers().iter() {
            error!(
                "Header: {} - {}",
                &h.as_str(),
                String::from_utf8_lossy(v.as_bytes())
            );

            if h.as_str().contains("content-type") {
                head.push_str(&format!(
                    "{}: {}\r\n",
                    &h.as_str(),
                    String::from_utf8_lossy(v.as_bytes())
                ));
            }
        }

        let b = resp.bytes().unwrap();
        head.push_str(&format!("content-length: {}\r\n\r\n", &b.len()));
        let b2 = head.as_bytes();

        //let b = concat_bytes!(b2,b)
        file.write_all(&b2).expect("write failed");
        file.write_all(&b).expect("write failed");
    }

    fn get_file_name(host: &str, http_path: &str) -> String {
        let mut file_path = format!(
            "{}/{}",
            dotenv::var("CACHE_PATH").expect("Expected CACHE_PATH in .env file!"),
            host
        );
        file_path = CacheIterator::sanitize_file_name(file_path);

        let mut file_name = format!("{}/{}", &file_path, http_path);

        if http_path.ends_with("/") || http_path.ends_with(host) {
            file_name = format!("{}/{}", file_path, "index.html");
        }

        file_name
    }
}
