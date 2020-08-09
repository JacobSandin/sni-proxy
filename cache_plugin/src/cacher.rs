use path::Path;
use std::{
    fs::{create_dir_all, File, OpenOptions},
    io::{prelude::*, BufReader, Read, Write},
    path,
};

#[allow(unused_imports)]
use logg::{debug, error, info, trace, warn};
use interfaces::Cacher;
pub struct SNICacher {}

impl SNICacher {
    pub fn new() -> SNICacher {
        SNICacher{}
    }
}


impl SNICacher {

    fn get_file_name(&self, host: &str, http_path: &str) -> String {
        let mut file_path = format!(
            "{}/{}",
            dotenv::var("CACHE_PATH").expect("Expected CACHE_PATH in .env file!"),
            host
        );
        file_path = self.sanitize_file_name(file_path);

        let mut file_name = format!("{}/{}", &file_path, http_path);

        if http_path.ends_with("/") || http_path.ends_with(host) {
            file_name = format!("{}/{}", file_path, "index.html");
        }

        file_name
    }

    fn sanitize_file_name(&self, file_name: String) -> String {
        file_name
            .replace("//", "/")
            .replace("\\/", "/")
            .replace("&", "!")
            .replace("?", "!")
            .replace("\\\\", "/")
    }

    fn write_add_to_path_file(
        &self,
        host_name: &str,
        forward: &str,
        get_request: &str,
    ) -> Option<bool> {
        let file_name = dotenv::var("CACHE_PATH").expect("Expected CACHE_PATH in .env file!");
        let file_name = format!("{}/{}/{}", file_name, &host_name, "paths_to_cache.txt");
        let file_name = self.sanitize_file_name(file_name);

        if !self.search_file_for_path(&file_name, &get_request).unwrap() {
            info!("Adding to file: {} ({})", &get_request, &file_name);

            let mut f = OpenOptions::new()
                .write(true)
                .append(true)
                .open(&file_name)
                .unwrap();

            if let Err(_) = writeln!(f, "http://{}{}", forward, &get_request) {
                error!("Could not write to file: {}", &file_name);
            }
        }
        Some(true)
    }

    fn search_file_for_path(&self, file_name: &str, path: &str) -> std::io::Result<bool> {
        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(file_name)?;
        let reader = BufReader::new(f);

        for line in reader.lines() {
            let l = line?;
            if l.contains(path) {
                //println!("{} -- {}", l, path);
                return Ok(true);
            }
        }
        Ok(false)
    }    
}



impl Cacher for SNICacher {
    #[allow(unused_variables)]
    fn cache_update_and_test_path(&mut self, host: &str, forward: &str, http_path: &str, data: &Vec<u8>) -> std::io::Result<bool> {
        let file_path = format!(
            "{}/{}",
            dotenv::var("CACHE_PATH").expect("Expected CACHE_PATH in .env file!"),
            host
        );
        let file_path = self.sanitize_file_name(file_path);
        match create_dir_all(&file_path) {
            Ok(_) => (),
            Err(_) => {
                return Ok(false);
            }
        }

        self.write_add_to_path_file(host, forward, &http_path.to_string());

        Ok(true)
    }
    fn cache_read_path(&self, host: &str, http_path: &str) -> Box<Option<Vec<u8>>> {
        let file_name = self.get_file_name(host, http_path);
        let file_name = self.sanitize_file_name(file_name);

        trace!("Cache filename IN: \r\n{}", &file_name);

        if Path::new(&file_name).exists() {
            let mut data = Vec::new();
            let mut file = File::open(&file_name).expect("Expecting file to open");
            file.read_to_end(&mut data).expect("Expecting file to be read ");
            trace!("Cache DATA OUT for file: \r\n{}", &file_name);
            return Box::new(Some(data.clone()));
        } else {
            Box::new(None)
        }
    }
    
}

