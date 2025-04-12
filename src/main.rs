use std::env;
use std::fs;
use std::path::Path;
use std::process;

use aes::Aes256;
use block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

const KEY: &[u8; 32] = b"@_#*&Reverse2806                ";
const IV: &[u8; 16] = b"!_#@2022_Skyfly)";

const SIGNATURE_LENGTH: usize = 48;

fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() <= SIGNATURE_LENGTH {
        return Err(format!(
            "Input data (length {}) is too short, must be longer than the signature length ({})",
            encrypted_data.len(),
            SIGNATURE_LENGTH
        ));
    }

    let data_to_decrypt = &encrypted_data[SIGNATURE_LENGTH..];

    let cipher = Aes256CbcDec::new(KEY.into(), IV.into());

    let mut buf = data_to_decrypt.to_vec();

    let decrypted_data = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|e| {
        format!(
            "Decryption failed (possibly wrong key/IV or padding error): {}",
            e
        )
    })?;

    Ok(decrypted_data.to_vec())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <input-file> <output-file>", args[0]);
        process::exit(1);
    }

    let input_path = Path::new(&args[1]);
    let output_path = Path::new(&args[2]);

    println!("Reading encrypted data from: {}", input_path.display());
    let encrypted_bytes = fs::read(input_path).map_err(|e| {
        format!(
            "Failed to read input file '{}': {}",
            input_path.display(),
            e
        )
    })?;

    println!("Decrypting data...");
    let decrypted_bytes = match decrypt(&encrypted_bytes) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error during decryption: {}", e);
            process::exit(1);
        }
    };

    println!("Writing decrypted data to: {}", output_path.display());
    fs::write(output_path, &decrypted_bytes).map_err(|e| {
        format!(
            "Failed to write output file '{}': {}",
            output_path.display(),
            e
        )
    })?;

    println!("Decryption complete.");

    Ok(())
}
