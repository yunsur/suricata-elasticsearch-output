// Copyright (c) 2021 Open Information Security Foundation
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// FFI helpers. This will be removed when these helpers get added to the
// Suricata rust code (where they belong).
mod ffi;

use elastic::client::{SyncClient, SyncClientBuilder};
use elastic::error::Error;
use serde_json::json;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc::TrySendError;
use suricata::conf::ConfNode;
use suricata::{SCLogError, SCLogNotice};

// Default configuration values.
const DEFAULT_URL: &str = "http://127.0.0.1:9200";
const DEFAULT_INDEX: &str = "suricata";
const DEFAULT_BUFFER_SIZE: &str = "65535";

#[derive(Debug, Clone)]
struct Config {
    url: String,
    index: String,
    buffer: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: DEFAULT_URL.into(),
            index: DEFAULT_INDEX.parse().unwrap(),
            buffer: DEFAULT_BUFFER_SIZE.parse().unwrap(),
        }
    }
}

impl Config {
    fn new(conf: &ConfNode) -> Result<Self, std::fmt::Error> {
        let url = if let Some(val) = conf.get_child_value("url") {
            val.to_string()
        } else {
            SCLogError!("url parameter required!");
            panic!();
        };

        let index = if let Some(val) = conf.get_child_value("index") {
            val.to_string()
        } else {
            SCLogError!("index parameter required!");
            panic!();
        };

        let buffer_size = match conf
            .get_child_value("buffer-size")
            .unwrap_or(DEFAULT_BUFFER_SIZE)
            .parse::<usize>()
        {
            Ok(size) => size,
            Err(_) => {
                SCLogError!("invalid buffer-size!");
                panic!();
            }
        };

        let config = Config {
            url: url.into(),
            index: index.into(),
            buffer: buffer_size,
        };
        Ok(config)
    }
}

struct Elasticsearch {
    client: SyncClient,
    config: Config,
    rx: std::sync::mpsc::Receiver<String>,
    count: usize,
}

impl Elasticsearch {
    fn new(config: Config, rx: std::sync::mpsc::Receiver<String>) -> Result<Self, Error> {
        let client = SyncClientBuilder::new()
            .static_node(format!("{url}", url = config.url))
            .params_fluent(|p| p.url_param("pretty", true))
            .build()?;

        Ok(Self {
            config,
            client,
            rx,
            count: 0,
        })
    }

    fn submit(&self, buf: &str) -> bool {
        let index = String::from(&self.config.index);
        let body: serde_json::Value = serde_json::from_str(buf).unwrap();

        let response = self
            .client
            .document()
            .index_raw(index, json!(body))
            .send();

        match response {
            Ok(_response) => true,
            Err(Error::Api(_e)) => false,
            Err(_e) => false,
        }
    }

    fn run(&mut self) {
        // Get a peekable iterator from the incoming channel. This allows us to
        // get the next message from the channel without removing it, we can
        // then remove it once its been sent to the server without error.
        //
        // Not sure how this will work with pipe-lining tho, will probably have
        // to do some buffering here, or just accept that any log records
        // in-flight will be lost.
        let mut iter = self.rx.iter().peekable();
        loop {
            if let Some(buf) = iter.peek() {
                self.count += 1;
                if !self.submit(&buf) {
                    SCLogError!("Failed to send event to Elasticsearch");
                    break;
                } else {
                    // Successfully sent.  Pop it off the channel.
                    let _ = iter.next();
                }
            } else {
                break;
            }
        }
        SCLogNotice!("Elasticsearch finished: count={}", self.count,);
    }
}

struct Context {
    tx: std::sync::mpsc::SyncSender<String>,
    count: usize,
    dropped: usize,
}

unsafe extern "C" fn output_open(conf: *const c_void, init_data: *mut *mut c_void) -> c_int {
    // Load configuration.
    let config = if conf.is_null() {
        Config::default()
    } else {
        Config::new(&ConfNode::wrap(conf)).unwrap()
    };

    let (tx, rx) = std::sync::mpsc::sync_channel(config.buffer);

    let mut elastic_client = match Elasticsearch::new(config, rx) {
        Ok(client) => {
            SCLogNotice!(
                "Elasticsearch initialize success with url:{:?} and index: {:?} and buffer-size: {:?}",
                client.config.url,
                client.config.index,
                client.config.buffer
            );
            client
        }
        Err(err) => {
            SCLogError!("Failed to initialize Elasticsearch client: {:?}", err);
            panic!()
        }
    };

    let context = Context {
        tx,
        count: 0,
        dropped: 0,
    };
    std::thread::spawn(move || elastic_client.run());

    *init_data = Box::into_raw(Box::new(context)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    let context = Box::from_raw(init_data as *mut Context);
    SCLogNotice!(
        "Elasticsearch finished: count={}, dropped={}",
        context.count,
        context.dropped
    );
    std::mem::drop(context);
}

unsafe extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);
    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len) {
        buf
    } else {
        return -1;
    };

    context.count += 1;

    if let Err(err) = context.tx.try_send(buf.to_string()) {
        context.dropped += 1;
        match err {
            TrySendError::Full(_) => {
                SCLogError!("Eve record lost due to full buffer");
            }
            TrySendError::Disconnected(_) => {
                SCLogError!("Eve record lost due to broken channel{}", err);
            }
        }
    }
    00
}

unsafe extern "C" fn init_plugin() {
    let file_type =
        ffi::SCPluginFileType::new("elasticsearch", output_open, output_close, output_write);
    ffi::SCPluginRegisterFileType(file_type);
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Rust plugins need to initialize some Suricata internals so stuff like logging works.
    suricata::plugin::init();

    // Register our plugin.
    ffi::SCPlugin::new("Elasticsearch Eve Filetype", "GPL-2.0", "Yunsur", init_plugin)
}
