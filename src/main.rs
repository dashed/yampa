#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]
extern crate serde;
extern crate serde_json;
extern crate argon2rs;
extern crate ring;
extern crate crypto;
extern crate byteorder;
extern crate secstr;
extern crate interactor;
extern crate ansi_term;
extern crate clap;
#[macro_use]
extern crate lazy_static;


use std::io::{Write, Read};
use std::path::Path;
use std::fs::File;
use std::error::Error;
use std::ascii::AsciiExt;

use serde::de::{self, Deserialize, Deserializer};

use clap::{Arg, App};

use byteorder::{BigEndian, WriteBytesExt};

const SALT_PREFIX : &'static str = "com.lyndir.masterpassword";

lazy_static! {
    static ref TEMPLATES_MAXIMUM: Vec<String> = vec![
        "anoxxxxxxxxxxxxxxxxx".to_string(),
        "axxxxxxxxxxxxxxxxxno".to_string()
    ];

    static ref TEMPLATES_LONG: Vec<String> = vec![
        "CvcvnoCvcvCvcv".to_string(), "CvcvCvcvnoCvcv".to_string(),
        "CvcvCvcvCvcvno".to_string(), "CvccnoCvcvCvcv".to_string(),
        "CvccCvcvnoCvcv".to_string(), "CvccCvcvCvcvno".to_string(),
        "CvcvnoCvccCvcv".to_string(), "CvcvCvccnoCvcv".to_string(),
        "CvcvCvccCvcvno".to_string(), "CvcvnoCvcvCvcc".to_string(),
        "CvcvCvcvnoCvcc".to_string(), "CvcvCvcvCvccno".to_string(),
        "CvccnoCvccCvcv".to_string(), "CvccCvccnoCvcv".to_string(),
        "CvccCvccCvcvno".to_string(), "CvcvnoCvccCvcc".to_string(),
        "CvcvCvccnoCvcc".to_string(), "CvcvCvccCvccno".to_string(),
        "CvccnoCvcvCvcc".to_string(), "CvccCvcvnoCvcc".to_string(),
        "CvccCvcvCvccno".to_string()
    ];

    static ref TEMPLATES_MEDIUM: Vec<String> = vec![
        "CvcnoCvc".to_string(), "CvcCvcno".to_string()
    ];

    static ref TEMPLATES_SHORT: Vec<String> = vec![
        "Cvcn".to_string()
    ];

    static ref TEMPLATES_BASIC: Vec<String> = vec![
        "aaanaaan".to_string(), "aannaaan".to_string(), "aaannaaa".to_string()
    ];

    static ref TEMPLATES_PIN: Vec<String> = vec![
        "nnnn".to_string()
    ];
}


// V
const TEMPLATE_V_UPPER : &'static [u8; 5] = b"AEIOU";
// v
const TEMPLATE_V_LOWER : &'static [u8; 5] = b"aeiou";
// C
const TEMPLATE_C_UPPER : &'static [u8; 21] = b"BCDFGHJKLMNPQRSTVWXYZ";
// c
const TEMPLATE_C_LOWER : &'static [u8; 21] = b"bcdfghjklmnpqrstvwxyz";
// A
const TEMPLATE_A_UPPER : &'static [u8; 26] = b"AEIOUBCDFGHJKLMNPQRSTVWXYZ";
// a
const TEMPLATE_A_UPPER_LOWER : &'static [u8; 52] = b"AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
// n (numeric)
const TEMPLATE_N : &'static [u8; 10] = b"0123456789";
// o (other)
const TEMPLATE_O : &'static [u8; 24] = b"@&%?,=[]_:-+*$#!'^~;()/.";
// X
const TEMPLATE_X : &'static [u8; 72] =
    b"AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";

macro_rules! template {
    ($TEMPLATE:expr, $seed_idx:expr) => {{
        $TEMPLATE[($seed_idx % $TEMPLATE.len()) as usize]
    }}
}

type Counter = u64;

#[derive(Clone)]
enum MasterKeyGen {

    // scrypt version that is compatible with http://masterpasswordapp.com/algorithm.html
    Classic,

    Argon2i
}

#[derive(Debug)]
enum TemplateJSON {
    Multiple(Vec<String>),
    Single(String)
}

struct TemplateJSONVisitor;

impl de::Visitor for TemplateJSONVisitor {

    type Value = TemplateJSON;

    fn visit_str<E>(&mut self, input: &str) -> Result<Self::Value, E>
        where E: de::Error
    {
        return self.visit_string(input.to_string());
    }

    fn visit_string<E>(&mut self, input: String) -> Result<Self::Value, E>
        where E: de::Error
    {

        match input.as_ref() {
            "MAXIMUM" | "MAX" => {
                return Ok(TemplateJSON::Multiple(TEMPLATES_MAXIMUM.clone()));
            },
            "LONG" => {
                return Ok(TemplateJSON::Multiple(TEMPLATES_LONG.clone()));
            },
            "MEDIUM" | "MED" => {
                return Ok(TemplateJSON::Multiple(TEMPLATES_MEDIUM.clone()));
            },
            "SHORT" => {
                return Ok(TemplateJSON::Multiple(TEMPLATES_SHORT.clone()));
            },
            "BASIC" => {
                return Ok(TemplateJSON::Multiple(TEMPLATES_BASIC.clone()));
            },
            "PIN" => {
                return Ok(TemplateJSON::Multiple(TEMPLATES_PIN.clone()));
            },
            _ => {
                return Ok(TemplateJSON::Single(input));
            }
        }

    }

    fn visit_seq<V>(&mut self, mut visitor: V) -> Result<Self::Value, V::Error>
        where V: de::SeqVisitor {

        let mut list = vec![];

        while let Some(value) = try!(visitor.visit()) {
            list.push(value);
        }

        try!(visitor.end());

        Ok(TemplateJSON::Multiple(list))

    }
}


impl Deserialize for TemplateJSON {

    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error>
        where D: Deserializer {

        deserializer.deserialize(TemplateJSONVisitor)
    }
}


#[derive(Debug, Deserialize)]
struct YampaEntry {
    location: String,
    login: String,
    counter: Option<Counter>,
    template: Option<TemplateJSON>
}

#[derive(Debug, Deserialize)]
struct YampaContents {
    name: String,
    list: Vec<YampaEntry>
}

pub fn main() {

    let matches = App::new("yampa")
        .version("0.1.0 (semver.org)")
        .author("Alberto Leal <mailforalberto@gmail.com> (github.com/dashed/yampa)")
        .about("Yet another master password app")
        .arg(Arg::with_name("file")
           .short("f")
           .long("file")
           .help("Input JSON file")
           .required(false)
           .takes_value(true)
        )
        .arg(Arg::with_name("classic")
           .short("c")
           .long("classic")
           .help("Classic master password app mode.")
           .required(false)
           .takes_value(false)
        )
        .arg(
            Arg::with_name("needle")
            .next_line_help(true)
            .help("Filter password generation to given search `needle`. Will match against `location` and `login`.")
            .required(false)
            .multiple(false)
        ).get_matches();

    let file_path = matches.value_of("file").unwrap_or("yampa.json");

    let path = Path::new(file_path);
    let display = path.display();

    let mut file = match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                                                   why.description()),
        Ok(file) => file,
    };

    let mut yampa_contents = String::new();
    match file.read_to_string(&mut yampa_contents) {
        Err(why) => panic!("couldn't read {}: {}", display,
                                                   why.description()),
        Ok(_) => {},
    }
    let yampa_contents = yampa_contents;

    let yampa_contents: YampaContents = match serde_json::from_str(&yampa_contents) {
        Ok(yampa_contents) => yampa_contents,
        Err(_) => {
            panic!("invalid JSON from: {}", display);
        }
    };

    let public_key = yampa_contents.name;
    println!("{:>11} {}", "Name:", public_key);

    let needle = match matches.value_of("needle") {
        Some(needle) => Some(needle.to_string().to_ascii_lowercase()),
        None => None
    };

    let mut master_password = None;

    if yampa_contents.list.len() <= 0 {
        println!("There are no entries to generate passwords for.");

        return;
    }

    let pass_type = if matches.is_present("classic") {
        MasterKeyGen::Classic
    } else {
        MasterKeyGen::Argon2i
    };

    for entry in yampa_contents.list.iter() {

        if needle.is_some() && has_needle(entry, &needle) || needle.is_none() {

            if master_password.is_none() {
                master_password = Some(read_password_console());
            }

            println!("");

            match master_password {
                Some(ref master_password) => {
                    output_entry(pass_type.clone(), entry, &public_key, master_password);
                },
                _ => {}
            }

        }

    }

}

#[inline]
fn has_needle(entry: &YampaEntry, needle: &Option<String>) -> bool {

    let ref location = entry.location;
    let ref login = entry.login;

    let should_output = match *needle {
        None => true,
        Some(ref needle) => {
            location.to_ascii_lowercase().contains(needle) ||
            login.to_ascii_lowercase().contains(needle)
        }
    };

    should_output

}

#[inline]
fn output_entry(pass_type: MasterKeyGen, entry: &YampaEntry, public_key: &String, master_password: &secstr::SecStr) {

    let ref location = entry.location;
    let ref login = entry.login;
    let counter = entry.counter.unwrap_or(1);

    let counter = if counter <= 0 {
        1
    } else {
        counter
    };

    // Based on: http://masterpasswordapp.com/algorithm.html

    // Step 1: Generate master key using argon2i (note: we do not use argon2d)

    let master_key = gen_master_key(pass_type.clone(), master_password, public_key);

    // Step 2: Generate template seed

    let template_seed = gen_template_seed(pass_type, master_key, location, login, counter);

    // Step 3: Generate password

    let templates = match *(&entry.template) {
        Some(ref template) => {
            match *template {
                TemplateJSON::Single(ref template) => {
                    vec![template.clone()]
                },
                TemplateJSON::Multiple(ref list) => {
                    list.clone()
                }
            }
        },
        None => TEMPLATES_LONG.clone()
    };

    let template = pick_template(template_seed.as_ref(), &templates);

    let password = gen_password(template_seed.as_ref(), template.clone());

    println!("{:>11} {}", "Location:", location);
    println!("{:>11} {}", "Login:", login);
    println!("{:>11} {}", "Counter:", counter);
    println!("{:>11} {}", "Template:", template);
    println!("{:>11} {}", "Password:", password);

}

#[inline]
fn gen_master_key(pass_type: MasterKeyGen, master_password: &secstr::SecStr, public_key: &String) -> Vec<u8> {

    match pass_type {
        MasterKeyGen::Argon2i => {

            let salt = format!("{salt_prefix}{public_key_len}{public_key}",
                salt_prefix = SALT_PREFIX,
                public_key_len = public_key.len(),
                public_key = public_key);

            let mut master_key: Vec<u8> = Vec::new();

            for byte in argon2rs::argon2i_simple(
                &String::from_utf8_lossy(master_password.unsecure()),
                &salt).iter() {
                master_key.push(*byte);
            }

            return master_key;

        },
        MasterKeyGen::Classic => {

            // Compatibility with scheme as described at: http://masterpasswordapp.com/algorithm.html

            let mut salt = vec![];
            salt.extend(SALT_PREFIX.bytes());
            salt.write_u32::<BigEndian>(public_key.len() as u32).unwrap();
            salt.extend(public_key.bytes());

            let log_n = 15; // log2(32768) = 15;
            let r = 8;
            let p = 2;

            let mut output = [0u8; 64];

            crypto::scrypt::scrypt(
                master_password.unsecure(),
                salt.as_slice(),
                &crypto::scrypt::ScryptParams::new(log_n, r, p),
                &mut output
            );

            let mut master_key: Vec<u8> = vec![];

            master_key.extend_from_slice(&output);

            return master_key;

        }
    }

}

#[inline]
fn gen_template_seed(
    pass_type: MasterKeyGen,
    master_key: Vec<u8>,
    location: &String,
    login: &String,
    counter: Counter) -> ring::digest::Digest {

    let source = format!("{location}{login}",
        location = location,
        login = login);

    let s_key = ring::hmac::SigningKey::new(&ring::digest::SHA256, master_key.as_slice());

    match pass_type {
        MasterKeyGen::Argon2i => {
            let hmac_input = format!("{salt_prefix}{source_len}{source}{counter}",
                salt_prefix = SALT_PREFIX,
                source_len = source.len(),
                source = source,
                counter = counter);

            let template_seed = ring::hmac::sign(&s_key, hmac_input.as_bytes());

            return template_seed;
        },
        MasterKeyGen::Classic => {

            let mut hmac_input = vec![];
            hmac_input.extend(SALT_PREFIX.bytes());
            hmac_input.write_u32::<BigEndian>(source.len() as u32).unwrap();
            hmac_input.extend(source.bytes());
            hmac_input.write_u32::<BigEndian>(counter as u32).unwrap();

            let template_seed = ring::hmac::sign(&s_key, hmac_input.as_slice());

            return template_seed;
        }
    };

}

#[inline]
fn pick_template(raw_seed: &[u8], templates: &Vec<String>) -> String {

    let templates_idx = (raw_seed[0] as usize) % templates.len();

    let template = templates[templates_idx].clone();

    return template;
}

#[inline]
fn gen_password(raw_seed: &[u8], template: String) -> String {

    let mut idx = 0;
    let result = template.chars().map(|x| {

        idx += 1;

        let seed_idx = raw_seed[idx] as usize;

        match x {
            'V' => template!(TEMPLATE_V_UPPER, seed_idx),
            'C' => template!(TEMPLATE_C_UPPER, seed_idx),
            'v' => template!(TEMPLATE_V_LOWER, seed_idx),
            'c' => template!(TEMPLATE_C_LOWER, seed_idx),
            'A' => template!(TEMPLATE_A_UPPER, seed_idx),
            'a' => template!(TEMPLATE_A_UPPER_LOWER, seed_idx),
            'n' => template!(TEMPLATE_N, seed_idx),
            'o' => template!(TEMPLATE_O, seed_idx),
            'X' | 'x' => template!(TEMPLATE_X, seed_idx),
            _ => {
                panic!("Invalid template: {}", template);
            }
        }

    }).collect::<Vec<_>>();


    String::from_utf8_lossy(result.as_slice()).into_owned()
}

// Lifted from: https://github.com/myfreeweb/freepass/blob/e83ac7718d2a7718b3c79f5d52cd463e3c391ea0/cli/src/util.rs#L22-L43
#[inline]
fn read_password_console() -> secstr::SecStr {
    secstr::SecStr::new(interactor::read_from_tty(|buf, b, tty| {
        if b == 4 {
            tty.write(b"\r                                       \r").unwrap();
            return;
        }
        let color_string = if buf.len() <= 0 {
            // Make it a bit harder to recover the password by e.g. someone filming how you're entering your password
            // Although if you're entering your password on camera, you're kinda screwed anyway

            b"\rEnter master password: <start typing>".to_vec()
        } else {
            let colors = hash_as_ansi(buf);
            format!("\rEnter master password: {}",
                ansi_term::ANSIStrings(&[
                    ansi_term::Colour::Fixed(colors[0] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[1] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[2] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[3] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[4] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[5] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[6] as u8).paint("**"),
                    ansi_term::Colour::Fixed(colors[7] as u8).paint("**"),
                ])).into_bytes()
        };
        tty.write(&color_string).unwrap();
    }, true, true).unwrap())
}

// Hashes given bytes and encodes the result as ANSI terminal colors.
#[inline]
fn hash_as_ansi(bytes: &[u8]) -> [u16; 8] {

    use crypto::digest::Digest;

    let mut sh = Box::new(crypto::sha2::Sha256::new());

    sh.input(bytes);

    let hash = sh.result_str();
    let hash = hash.as_bytes();

    let mut colors: [u16; 8] = [0; 8];
    for i in 0..8 {
        colors[i] = 16 + (hash[i] as u16 % 216);
    }
    colors
}


#[cfg(test)]
mod tests {

    extern crate rusterpassword;
    extern crate secstr;

    #[test]
    fn test_compatibility() {

        let master_password = secstr::SecStr::from("Correct Horse Battery Staple".to_string());
        let public_key = "Cosima Niehaus".to_string();

        let location = "twitter.com".to_string();
        let login = "".to_string();
        let counter = 5;
        let pass_type = super::MasterKeyGen::Classic;

        // master key

        let expected_master_key = rusterpassword::gen_master_key(
            master_password.clone(),
            &public_key.clone()
        ).unwrap();

        let actual_master_key = super::gen_master_key(pass_type.clone(), &master_password, &public_key);

        assert_eq!(expected_master_key.unsecure(), actual_master_key.as_slice());

        // template seed

        let expected_seed = rusterpassword::gen_site_seed(
            &expected_master_key,
            &location,
            counter as u32
        ).unwrap();

        let actual_seed = super::gen_template_seed(pass_type, actual_master_key, &location, &login, counter);

        assert_eq!(expected_seed.unsecure(), actual_seed.as_ref());

        // password generation

        let expected_pass = rusterpassword::gen_site_password(
            &expected_seed,
            super::TEMPLATES_MAXIMUM
                .clone()
                .iter()
                .map(|x| x.as_ref())
                .collect::<Vec<&str>>()
                .as_slice()
            );

        let template = super::pick_template(actual_seed.as_ref(), &super::TEMPLATES_MAXIMUM);
        let actual_pass = super::gen_password(actual_seed.as_ref(), template);

        assert_eq!(expected_pass.unsecure(), actual_pass.as_bytes());

    }


    // TODO: more tests
}
