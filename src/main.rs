#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]
#![warn(clippy::semicolon_if_nothing_returned)]

use ark_circom::circom::R1CSFile;
use nargo::artifacts::program::ProgramArtifact;
use std::{
    collections::BTreeMap,
    env::current_dir,
    fs::{File, OpenOptions},
    io::{BufReader, Write},
    path::{Path, PathBuf},
};

use noirc_errors::debug_info::DebugInfo;

mod abi;
mod circuit;

use abi::abi_from_symbols;
use circuit::acir_circuit_from_r1cs_file;

fn main() -> anyhow::Result<()> {
    let root = current_dir().unwrap();
    let r1cs = root.join("example/circuit.r1cs");
    let reader = OpenOptions::new().read(true).open(r1cs)?;
    let reader = BufReader::new(reader);

    let r1cs_file: R1CSFile<ark_bn254::Bn254> = R1CSFile::new(reader)?;

    let symbols = root.join("example/circuit.sym");
    let reader = OpenOptions::new().read(true).open(symbols)?;
    let reader = BufReader::new(reader);

    let abi = abi_from_symbols(&r1cs_file.header, reader);
    let acir = acir_circuit_from_r1cs_file(r1cs_file);

    let artifact = ProgramArtifact {
        noir_version: "circom".to_string(),
        hash: 0,
        abi,
        bytecode: acir,
        debug_symbols: DebugInfo::default(),
        file_map: BTreeMap::default(),
    };

    write_to_file(
        &serde_json::to_vec(&artifact).unwrap(),
        &PathBuf::from("acir.json"),
    );

    Ok(())
}

fn write_to_file(bytes: &[u8], path: &Path) -> String {
    let display = path.display();

    let parent_dir = path.parent().unwrap();
    if !parent_dir.is_dir() {
        std::fs::create_dir_all(parent_dir).unwrap();
    }

    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't create {display}: {why}"),
        Ok(file) => file,
    };

    match file.write_all(bytes) {
        Err(why) => panic!("couldn't write to {display}: {why}"),
        Ok(_) => display.to_string(),
    }
}
