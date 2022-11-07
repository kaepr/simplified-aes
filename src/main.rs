/*!
# Simplified AES

Input: `16bit` plaintext

Output: `16bit` ciphertext

Key: `16bit` key

*/

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

/// # Shift Rows
/// Returns the state after swapping the lower nibbles
fn shift_rows(state: u16) -> u16 {
    let lower_half = state & 0xFF;
    println!("{:#018b}", lower_half);

    state
}

/// # Add Key
/// Returns the xor of given state and key
fn add_key(state: u16, key: u16) -> u16 {
    state ^ key
}

/// # Nibble substitution
/// Leftmost 2 bits of nibble used as row index.
/// Rightmost 2 bits of nibble used as column index
///
///
fn nibble_sub(state: u16) -> u16 {
    state
}

fn main() {
    shift_rows(255);

    println!("{:#018b}", 0xB);
    println!("Hello, world!");
}
