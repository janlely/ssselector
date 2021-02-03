extern crate pretty_env_logger;
#[macro_use] extern crate log;
extern crate base64;
extern crate tokio;
extern crate tokio_ping;
extern crate serde;
extern crate reqwest;
extern crate serde_millis;
extern crate clap;
extern crate shellexpand;
use clap::{Arg, App};
use serde::{Serialize, Deserialize};
use serde_json;


use std::str;
use std::sync::{Arc, Mutex};
use std::process;
use pbr::ProgressBar;
use std::time::Duration;
use std::io::prelude::*;

use dns_lookup::lookup_host;

use surge_ping::Pinger;
use tokio::task;
use tokio::runtime::Runtime;
use tokio::signal::unix::{signal, SignalKind};
use tokio::process::Command;

// use shadowsocks::{run_server, Config, ConfigType};
use std::net::TcpStream;
use std::fs::OpenOptions;
use std::io::{self, BufRead};
use shadowsocks::{run_server, Config, ConfigType};



#[derive(Serialize, Deserialize, Debug)]
struct SSConfig {
    server: String,
    server_port: u32,
    method: String,
    password: String,
    #[serde(with = "serde_millis")]
    delay: Duration,
    local_address: String,
    local_port: u32,
    timeout: u32,
    remark: String,
    available: bool
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let matches = App::new("ssselector")
        .version("1.0")
        .arg(Arg::with_name("subscribe")
            .short("c")
            .long("subscribe")
            .value_name("STRING")
            .help("the subscribe url"))
        .arg(Arg::with_name("select next")
            .multiple(true)
            .short("n")
            .long("next")
            .help("select the next available server"))
        .arg(Arg::with_name("target file")
            .short("t")
            .default_value("~/.ssselector.config")
            .long("target")
            .value_name("FILE")
            .help("target file to store server configs"))
        .arg(Arg::with_name("process id")
            .short("p")
            .default_value("~/.ssselector.proc")
            .value_name("FILE")
            .long("proc")
            .help("process id file"))
        .get_matches();
    let target = shellexpand::tilde(matches.value_of("target file").unwrap());
    let proc_id_file = shellexpand::tilde(matches.value_of("process id").unwrap());
    if let Some(url) = matches.value_of("subscribe") {
        do_subscribe(url, &target).await?;
        write_proc_id(&proc_id_file).await?;
        let mut stream = signal(SignalKind::hangup())?;
        loop {
            let rt = start_ss(target.as_ref()).await?;
            stream.recv().await;
            info!("received hangup SIG, select");
            rt.shutdown_background();
            inc_index(target.as_ref()).await?;
        }
    }
    if matches.occurrences_of("select next") > 0 {
        send_sig(&proc_id_file).await?;
    }
    Ok(())
}

async fn send_sig(proc_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(file) = OpenOptions::new().read(true).open(proc_file) {
        let mut line_iter = io::BufReader::new(file).lines();
        let idx: usize = line_iter.next().unwrap().unwrap().parse()?;
        let mut child = Command::new("kill")
                .arg("-s")
                .arg("SIGHUP")
                .arg(format!("{}", idx))
                .spawn()
                .expect("fail to send SIGHUP to ssselector");
        child.wait().await?;
    }
    Ok(())
}

async fn write_proc_id(proc_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("writing proc id");
    let mut file = OpenOptions::new().read(true).create(true).open(proc_file)?;
    let proc_id = process::id();
    file.write_all(format!("{}\n", proc_id).as_bytes())?;
    Ok(())
}

async fn start_ss(target: &str) -> Result<Runtime, Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    let file = OpenOptions::new().read(true).open(target)?;
    let mut line_iter = io::BufReader::new(file).lines();
    let idx: usize = line_iter.next().unwrap().unwrap().parse()?;
    let config = line_iter.skip(idx).next().unwrap()?;
    let config = Config::load_from_str(&config, ConfigType::Server).unwrap();
    info!("starting ss-local");
    rt.spawn(run_server(config));
    Ok(rt)
}

async fn inc_index(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = OpenOptions::new().read(true).open(target)?;
    let mut line_iter = io::BufReader::new(file).lines();
    let idx: u32 = line_iter.next().unwrap().unwrap().parse()?;
    debug!("current index: {}", idx);
    let mut buf: Vec<u8> = vec![];
    format!("{}\n", idx + 1).chars().for_each(|c| {
        buf.push(c as u8);
    });
    line_iter.for_each(|line| {
        line.unwrap().chars().for_each(|c| {
            buf.push(c as u8);
        });
        buf.push('\n' as u8);
    });
    let mut file = OpenOptions::new().write(true).open(target)?;
    file.write_all(buf.as_slice())?;
    Ok(())
}

fn resolve_ip(hostname: &str) -> String {
    let ips: Vec<std::net::IpAddr> = lookup_host(hostname).unwrap();
    ips.first().unwrap().to_string()
}

fn base64_decode_string(input: &str) -> String {
    debug!("decode input: {}", input);
    let bs = base64::decode_config(if input.len() % 4 == 1 {
        input.get(0..input.len()-1).unwrap()
    } else {
        input
    }, base64::URL_SAFE).unwrap();
    str::from_utf8(bs.as_slice()).unwrap().to_string()
}

fn parse_base(input: &str) -> (String, u32, String, String) {
    let v = input.split(':').collect::<Vec<&str>>();
    (v[0].to_string(), v[1].parse::<u32>().unwrap(), v[3].to_string(), base64_decode_string(v[5]))
}

fn parse_extend(input: &str) -> String {
    let params = input.split('&').collect::<Vec<&str>>();
    for param in params.into_iter() {
        let key_value = param.split('=').collect::<Vec<&str>>();
        if key_value[0] == "remarks" {
            return base64_decode_string(&key_value[1])
        }
    }
    String::new()
}

async fn do_subscribe(url: &str, target: &str) -> Result<(), Box<dyn std::error::Error>> {

	info!("fetching ssr link list data...");
    let body = reqwest::get(url).await?.text().await?;
    let ssr_links = base64_decode_string(body.as_str());

	info!("parsing ssr link list...");
    let mut configs: Vec<SSConfig> = ssr_links.split('\n').collect::<Vec<&str>>().iter()
    .filter(|link| link.len() > 0)
    .map(|link| {
        let b64 = match link {
            b if link.starts_with("ssr://") => b.to_string().get(6..).unwrap().to_string(),
            b if link.starts_with("ss://")  => b.to_string().get(5..).unwrap().to_string(),
            b                               => panic!("unsupported link: {}", b)
        };
        let link_string = base64_decode_string(b64.as_str());
        let base_extend = link_string.split('?').collect::<Vec<&str>>();
        let (sa, sp, m, ps) = parse_base(base_extend[0]);
        let remark = parse_extend(base_extend[1]);
        SSConfig {
            server: resolve_ip(sa.as_str()),
            server_port: sp,
            method: m,
            password: ps,
            delay: Duration::from_secs(60 * 60000),
            local_address: "127.0.0.1".to_string(),
            local_port: 1080,
            timeout: 300,
            remark: remark,
            available: false
        }
    }).collect();
    info!("testing connecting with servers...");
    let mut pb = ProgressBar::new(configs.len() as u64);
    pb.format("╢▌▌░╟");
    for cfg in configs.iter_mut() {
        let host = format!("{}:{}", cfg.server, cfg.server_port);
        match TcpStream::connect_timeout(&host.parse().unwrap(), Duration::from_millis(1000)) {
            Ok(_) => cfg.available = true,
            Err(_) => ()
        }
        pb.inc();
    }
    pb.finish();
    info!("pinging servers...");
    let pb = Arc::new(Mutex::new(ProgressBar::new(configs.len() as u64)));
    pb.lock().unwrap().format("╢▌▌░╟");
    let configs = Arc::new(Mutex::new(configs));
    let len = configs.lock().unwrap().len();
    for i in 0..len {
        let cfgs = Arc::clone(&configs);
        let pb = Arc::clone(&pb);
        task::spawn(async move {
            let addr = cfgs.lock().unwrap()[i].server.parse().unwrap();
            let mut pinger = Pinger::new(addr).unwrap();
            pinger.timeout(Duration::from_secs(1));
            let mut sum_rtt = Duration::from_secs(0);
            for idx in 0..3 {
                debug!("ping {} time for: {}", idx, addr);
                let res = pinger.ping(idx).await;
                match res {
                    Ok((_, dur)) => {
                        sum_rtt += dur;
                    },
                    Err(_) => {
                        debug!("error ping for: {}", addr);
                        sum_rtt = Duration::from_secs(3600);
                        break
                    }
                }
            }
            if cfgs.lock().unwrap()[i].available {
                cfgs.lock().unwrap()[i].delay = sum_rtt.checked_div(3).unwrap();
            }
            debug!("ping result for: {} is: {:?}", addr, cfgs.lock().unwrap()[i].delay);
            pb.lock().unwrap().inc();
        }).await?;
    }
    pb.lock().unwrap().finish();
    info!("sorting servers by ping delay");
    configs.lock().unwrap().sort_by(|a,b| {
        a.delay.cmp(&b.delay)
    });
    write_configs(&configs.lock().unwrap(), target).await?;
    Ok(())
}

async fn write_configs(configs: &Vec<SSConfig>, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = OpenOptions::new().create(true).write(true).open(target)?;
    let mut file = io::LineWriter::new(file);
    file.write(b"0\n")?;
    for cfg in configs {
        let json_str = serde_json::to_string(cfg).unwrap();
        file.write_all(json_str.as_bytes())?;
        file.write(&['\n' as u8])?;
    }
    Ok(())
}