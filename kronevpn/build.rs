fn main() {
    // Windows: Manifest (Adminrechte fuer den Netzwerkadapter), Symbol und Versionsangaben einbetten.
    // Die Version kommt immer aus Cargo.toml (res/kronevpn.rc ist nur die Vorlage).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap().replace('\\', "/");
        let ver = std::env::var("CARGO_PKG_VERSION").unwrap();
        let mut n: Vec<String> = ver.split('.').map(|x| x.chars().take_while(|c| c.is_ascii_digit()).collect::<String>()).collect();
        n.resize(4, "0".into());
        let nums = n.iter().map(|x| if x.is_empty() { "0" } else { x.as_str() }).collect::<Vec<_>>().join(",");
        let src = std::fs::read_to_string("res/kronevpn.rc").unwrap();
        let rc: String = src
            .lines()
            .map(|l| {
                let t = l.trim_start();
                if t.starts_with("FILEVERSION ") {
                    format!("FILEVERSION {nums}")
                } else if t.starts_with("PRODUCTVERSION ") {
                    format!("PRODUCTVERSION {nums}")
                } else if t.starts_with("VALUE \"FileVersion\"") {
                    format!("      VALUE \"FileVersion\", \"{ver}\"")
                } else if t.starts_with("VALUE \"ProductVersion\"") {
                    format!("      VALUE \"ProductVersion\", \"{ver}\"")
                } else {
                    l.replace("\"kronevpn.manifest\"", &format!("\"{dir}/res/kronevpn.manifest\"")).replace("\"kronevpn.ico\"", &format!("\"{dir}/res/kronevpn.ico\""))
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("kronevpn.rc");
        std::fs::write(&out, rc + "\n").unwrap();
        embed_resource::compile(&out, embed_resource::NONE).manifest_required().unwrap();
    }
    println!("cargo:rerun-if-changed=res/kronevpn.rc");
    println!("cargo:rerun-if-changed=res/kronevpn.manifest");
    println!("cargo:rerun-if-changed=res/kronevpn.ico");
    println!("cargo:rerun-if-changed=wintun/wintun.dll");
    println!("cargo:rerun-if-changed=../Cargo.toml");
}
