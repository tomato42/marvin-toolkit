use anyhow::{Context as _, Result};
use clap::Parser;
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Encrypt, RsaPrivateKey};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(about = "Measure timing of PKCS#1 v1.5 RSA decryption using RustCrypto rsa crate")]
struct Args {
    /// File with the ciphertexts to decrypt
    #[arg(short, long)]
    infile: PathBuf,

    /// File to write the timing data to
    #[arg(short, long)]
    outfile: PathBuf,

    /// The private key to use for decryption
    #[arg(short, long)]
    keyfile: PathBuf,

    /// Size of individual ciphertexts for decryption
    #[arg(short = 'n', long)]
    size: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let pem = fs::read_to_string(&args.keyfile)
        .with_context(|| format!("unable to read private key from {}", args.keyfile.display()))?;

    let privkey = RsaPrivateKey::from_pkcs8_pem(&pem)?;

    let mut infile = fs::OpenOptions::new()
        .read(true)
        .open(&args.infile)
        .with_context(|| format!("unable to open {} for reading", args.infile.display()))?;

    let mut outfile = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&args.outfile)
        .with_context(|| format!("unable to open {} for writing", args.outfile.display()))?;

    writeln!(outfile, "raw times")?;

    loop {
        let mut buffer = vec![0; args.size];

        let n = infile.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        assert!(n == buffer.len());

        let now = Instant::now();
        let _ = privkey.decrypt(Pkcs1v15Encrypt, &buffer);
        writeln!(outfile, "{}", now.elapsed().as_nanos())?;
    }

    println!("done");
    Ok(())
}
