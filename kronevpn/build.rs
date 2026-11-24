fn main() {
    // Windows: Manifest (Adminrechte fuer den Netzwerkadapter) und Symbol einbetten
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("res/kronevpn.rc", embed_resource::NONE).manifest_required().unwrap();
    }
    println!("cargo:rerun-if-changed=res/kronevpn.rc");
    println!("cargo:rerun-if-changed=res/kronevpn.manifest");
    println!("cargo:rerun-if-changed=wintun/wintun.dll");
}
