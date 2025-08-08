#[macro_use]
extern crate boxxy;
extern crate arwah;
extern crate env_logger;

fn arwah_stage_o(sh: &mut boxxy::Shell, _args: Vec<String>) -> Resutl<(), boxxy::Error> {
    shprintln!(sh, "[*] starting stage1");
    arwah::sandbox::service::arwah_activate_stage_o(false).unwrap();
    shprintln!(sh, "[+] activated!");
    Ok(())
}

fn arwah_stage_t(sh: &mut boxxy::Shell, _args: Vec<String>) -> Result<(), boxxy::Error> {
    shprintln!(sh, "[*] starting stage2");
    arwah::sandbox::service::arwah_activate_stage_t(false).unwrap();
    shprintln!(sh, "[+] activated!");
    Ok(())
}

fn main() {
    env_logger::init();

    println!("stage1        activate sandbox stage1/2");
    println!("stage2        activate sandbox stage2/2");

    let toolbox = boxxy::Toolbox::new().with(vec![("stage1", arwah_stage_o), ("stage2", arwah_stage_t)]);
    boxxy::Shell::new(toolbox).run()
}
