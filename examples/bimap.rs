use std::net::Ipv4Addr;

use bimap::BiMap;

fn main() {
    let mut map: BiMap<Ipv4Addr, String> = Default::default();
    map.insert("192.168.2.1".parse().unwrap(), "fedora".to_owned());
    map.insert("192.168.2.2".parse().unwrap(), "example.com".to_owned());
    let sx = serde_json::to_string(&map).unwrap();

    println!("{}", sx);
    let map: BiMap<Ipv4Addr, String> = serde_json::from_str(&sx).unwrap();
    dbg!(&map);
}
