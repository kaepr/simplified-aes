/*!
# Simplified AES

Input: `16bit` plaintext

Output: `16bit` ciphertext

Key: `16bit` key

*/

use std::io;

trait NibbleUtil {
    fn get_nibble_val(&self, idx: u8) -> u16;
    fn get_lower_half(&self) -> u16;
    fn get_upper_half(&self) -> u16;
    fn get_leftmost_2bits(&self) -> u8;
    fn get_rightmost_2bits(&self) -> u8;
}

impl NibbleUtil for u16 {
    /// # Nibble Mapping
    ///
    /// 0 => S00 = [b0 b1 b2 b3]
    ///
    /// 1 => S01 = [b8 b9 b10 b11]
    ///
    /// 2 => S10 = [b4 b5 b6 b7]
    ///
    /// 3 => S11 = [b12 b13 b14 b15]
    fn get_nibble_val(&self, idx: u8) -> u16 {
        let shifted = match idx {
            0 => *self >> 12u8,
            1 => *self >> 4u8,
            2 => *self >> 8u8,
            3 => *self,
            _ => panic!("Invalid index: {} passed!", idx),
        };

        shifted & 0x000F
    }

    fn get_lower_half(&self) -> u16 {
        self & 0x00FF
    }

    fn get_upper_half(&self) -> u16 {
        (self >> 8u8) & 0x00FF
    }

    /// Assumes that input is a nibble value
    fn get_leftmost_2bits(&self) -> u8 {
        ((self >> 2u8) & 0x0003) as u8
    }

    /// Assumes that input is a nibble value
    fn get_rightmost_2bits(&self) -> u8 {
        (self & 0x0003) as u8
    }
}

static S_BOX: [[u8; 4]; 4] = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7],
];

static INV_S_BOX: [[u8; 4]; 4] = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE],
];

static MULT_TABLE: [[u8; 16]; 16] = [
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    ],
    [
        0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD,
    ],
    [
        0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2,
    ],
    [
        0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9,
    ],
    [
        0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6,
    ],
    [
        0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4,
    ],
    [
        0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB,
    ],
    [
        0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1,
    ],
    [
        0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE,
    ],
    [
        0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC,
    ],
    [
        0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3,
    ],
    [
        0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8,
    ],
    [
        0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7,
    ],
    [
        0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5,
    ],
    [
        0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA,
    ],
];

/// # Shift Rows
/// Returns the state after swapping the lower nibbles
fn shift_row(state: u16) -> u16 {
    let s00 = state.get_nibble_val(0);
    let s01 = state.get_nibble_val(1);
    let s10 = state.get_nibble_val(2);
    let s11 = state.get_nibble_val(3);

    (s00 << 12) | (s01 << 4) | (s11 << 8) | s10
}

/// # Used to rotate key
fn shift_row_byte(state: u16) -> u16 {
    let n1 = state.get_nibble_val(1);
    let n3 = state.get_nibble_val(3);
    (n3 << 4u8) | n1
}

/// # Add Key
/// Returns the xor of given state and key
fn add_key(state: u16, key: u16) -> u16 {
    state ^ key
}

/// # Nibble substitution
/// Leftmost 2 bits of nibble used as row index.
/// Rightmost 2 bits of nibble used as column index
fn nibble_sub(state: u16, is_inverse: bool) -> u16 {
    let s00 = nib_sub(state, 0, is_inverse);
    let s01 = nib_sub(state, 1, is_inverse);
    let s10 = nib_sub(state, 2, is_inverse);
    let s11 = nib_sub(state, 3, is_inverse);

    (s00 << 12) | (s01 << 4) | (s10 << 8) | s11
}

fn nib_sub(state: u16, idx: u8, is_inverse: bool) -> u16 {
    let nib_val = state.get_nibble_val(idx);

    let row_idx = nib_val.get_leftmost_2bits();
    let col_idx = nib_val.get_rightmost_2bits();

    // println!(
    //     "State: {:#X}, Idx: {}, Nib Val: {:#b} Row Idx: {:#b}, Col Idx: {:#b}",
    //     state, idx, nib_val, row_idx, col_idx
    // );

    match is_inverse {
        true => INV_S_BOX[row_idx as usize][col_idx as usize].into(),
        false => S_BOX[row_idx as usize][col_idx as usize].into(),
    }
}

fn key_expansion(key: u16) -> Vec<u16> {
    let mut expanded_key = Vec::new();

    let rcon_1: u8 = 0b10000000;
    let rcon_2: u8 = 0b00110000;

    let w0 = key.get_upper_half() as u8;
    let w1 = key.get_lower_half() as u8;
    let w2 = w0 ^ rcon_1 ^ ((nibble_sub(shift_row_byte(w1.into()), false) & 0x00FF) as u8);
    let w3 = w2 ^ w1;
    let w4 = w2 ^ rcon_2 ^ ((nibble_sub(shift_row_byte(w3.into()), false) & 0x00FF) as u8);
    let w5 = w4 ^ w3;

    expanded_key.push(((w0 as u16) << 8) | (w1 as u16));
    expanded_key.push(((w2 as u16) << 8) | (w3 as u16));
    expanded_key.push(((w4 as u16) << 8) | (w5 as u16));

    expanded_key
}

fn mix_col(state: u16) -> u16 {
    let s00 = state.get_nibble_val(0);
    let s01 = state.get_nibble_val(1);
    let s10 = state.get_nibble_val(2);
    let s11 = state.get_nibble_val(3);

    println!(
        "Before Mix Col\n
        s00 = {:#06b}\n
        s01 = {:#06b}\n
        s10 = {:#06b}\n
        s11 = {:#06b}\n
    ",
        s00, s01, s10, s11
    );

    let sn00 = s00 ^ get_mult_val(4, s10);
    let sn10 = s10 ^ get_mult_val(4, s00);
    let sn01 = s01 ^ get_mult_val(4, s11);
    let sn11 = s11 ^ get_mult_val(4, s01);

    println!(
        "Before Mix Col\n
        sn00 = {:#06b}\n
        sn01 = {:#06b}\n
        sn10 = {:#06b}\n
        sn11 = {:#06b}\n
    ",
        sn00, sn01, sn10, sn11
    );

    (sn00 << 12) | (sn01 << 4) | (sn10 << 8) | sn11
}

fn get_mult_val(fst: u16, snd: u16) -> u16 {
    MULT_TABLE[fst as usize][snd as usize] as u16
}

fn inv_mix_col(state: u16) -> u16 {
    let s00 = state.get_nibble_val(0);
    let s01 = state.get_nibble_val(1);
    let s10 = state.get_nibble_val(2);
    let s11 = state.get_nibble_val(3);

    let sn00 = get_mult_val(9, s00) ^ get_mult_val(2, s10);
    let sn10 = get_mult_val(2, s00) ^ get_mult_val(9, s10);
    let sn01 = get_mult_val(9, s01) ^ get_mult_val(2, s11);
    let sn11 = get_mult_val(2, s01) ^ get_mult_val(9, s11);

    (sn00 << 12) | (sn01 << 4) | (sn10 << 8) | sn11
}

fn encrypt(plaintext: u16, keys: &Vec<u16>) -> u16 {
    // Add Round 0 Key
    let mut cipher = add_key(plaintext, keys[0]);

    println!(
        "After add Round 0 key: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    // Round 1
    // Nibble Sub
    cipher = nibble_sub(cipher, false);

    println!(
        "After Nib Sub 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );

    // Shift Row
    cipher = shift_row(cipher);

    println!(
        "After Shift Row 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    // Mix Col
    cipher = mix_col(cipher);

    println!(
        "After Mix Col 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    // Add Round 1 Key
    cipher = add_key(cipher, keys[1]);

    println!(
        "After add key 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    // Round 2

    // Nibble Sub
    cipher = nibble_sub(cipher, false);

    println!(
        "After Nib Sub 2 Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    // Shift Row
    cipher = shift_row(cipher);

    println!(
        "After Shift Row 2 Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    // Add Round 2 Key
    cipher = add_key(cipher, keys[2]);

    println!(
        "After round key 2: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        cipher, cipher
    );
    cipher
}

fn decrypt(ciphertext: u16, keys: &Vec<u16>) -> u16 {
    println!("In decryption process");

    // Add Round 0 Key
    let mut plaintext = add_key(ciphertext, keys[2]);

    println!(
        "After add Round 0 key: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Round 1

    // Shift Row
    plaintext = shift_row(plaintext);

    println!(
        "After Shift Row 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Nibble Sub
    plaintext = nibble_sub(plaintext, true);

    println!(
        "After Nib Sub 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Add Round 1 Key
    plaintext = add_key(plaintext, keys[1]);

    println!(
        "After add key 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Mix Col
    plaintext = inv_mix_col(plaintext);

    println!(
        "After Mix Col 1: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Round 2

    // Shift Row
    plaintext = shift_row(plaintext);

    println!(
        "After Shift Row 2 Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Nibble Sub
    plaintext = nibble_sub(plaintext, true);

    println!(
        "After Nib Sub 2 Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    // Add Round 2 Key
    plaintext = add_key(plaintext, keys[0]);

    println!(
        "After round key 2: Ciphertext : \nHex : {:#X}\nBinary : {:#018b}",
        plaintext, plaintext
    );

    plaintext
}

fn read_user_input(input: &mut String) -> String {
    input.clear();

    io::stdin()
        .read_line(input)
        .expect("error: failed to read user input");

    input.trim().to_string()
}

fn parse_user_input(input: &str) -> u16 {
    println!("Input to parse user input: {}", input);

    if input.trim().contains("0x") {
        let upper = input
            .trim()
            .strip_prefix("0x")
            .expect("Invalid hexadecimal number entered")
            .to_ascii_uppercase()
            .to_string();

        let val = u16::from_str_radix(&upper, 16)
            .expect("Enter valid hexadecimal number in valid range (0..255)");
        return val;
    }

    let val = u16::from_str_radix(&input.trim(), 2).expect("Enter valid bitstring of length 16");
    val
}

fn main() {
    println!("Simplified AES Demo");
    let mut input = String::new();

    loop {
        println!("Enter Choice: ");
        println!("Enter 1 to generate ciphertext.");
        println!("Enter 2 to get plaintext back.");
        println!("Ctrl-C to exit program.");

        let choice = read_user_input(&mut input)
            .parse::<u16>()
            .expect("incorrect choice provided. exiting");

        match choice {
            1 => {
                println!("enter plaintext: (prefix by 0x and letters in capitals to input in hexadecimal)");
                let ptext = read_user_input(&mut input);
                let plaintext = parse_user_input(&ptext);
                println!(
                    "plaintext:\nhex : {:#x}\nbinary : {:#018b}",
                    plaintext, plaintext
                );

                println!(
                    "enter key: (prefix by 0x and letters in capitals to input in hexadecimal)"
                );
                let ktext = read_user_input(&mut input);
                let key = parse_user_input(&ktext);
                println!("key : \nhex : {:#x}\nbinary : {:#018b}", key, key);

                let keys = key_expansion(key);

                println!("keys generated after expansion: \n");
                for &key_val in keys.iter() {
                    println!("key : \nhex : {:#x}\nbinary : {:#018b}", key_val, key_val);
                }

                let cipher_text = encrypt(plaintext, &keys);

                println!(
                    "ciphertext : \nhex : {:#x}\nbinary : {:#018b}",
                    cipher_text, cipher_text
                );
            }
            2 => {
                println!("enter ciphertext: (prefix by 0x and letters in capitals to input in hexadecimal)");
                let ctext = read_user_input(&mut input);
                let ciphertext = parse_user_input(&ctext);

                println!(
                    "ciphertext:\nhex : {:#x}\nbinary : {:#018b}",
                    ciphertext, ciphertext
                );

                println!(
                    "enter key: (prefix by 0x and letters in capitals to input in hexadecimal)"
                );
                let ktext = read_user_input(&mut input);
                let key = parse_user_input(&ktext);
                println!("key : \nhex : {:#x}\nbinary : {:#018b}", key, key);

                let keys = key_expansion(key);

                println!("keys generated after expansion: \n");
                for &key_val in keys.iter() {
                    println!("key : \nhex : {:#x}\nbinary : {:#018b}", key_val, key_val);
                }

                let plain_text = decrypt(ciphertext, &keys);

                println!(
                    "plain_text : \nhex : {:#x}\nbinary : {:#018b}",
                    plain_text, plain_text
                );
            }
            _ => panic!("Incorrect choice provided!"),
        }
    }
}
