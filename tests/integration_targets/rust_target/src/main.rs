#![cfg_attr(target_os = "android", no_std)]
#![cfg_attr(target_os = "android", no_main)]

use core::str;
use vmp_macros::{vm_func, vm_string};

#[used]
#[vm_string]
#[no_mangle]
pub static RUST_SECRET_BYTES: [u8; 29] = *b"rust-target::vm-string::sigma";

#[no_mangle]
pub static RUST_VISIBLE_SECRET: [u8; 27] = *b"rust-target::runtime::sigma";

#[vm_func]
#[no_mangle]
pub extern "C" fn protected_mix_rust(x: u64, y: u64) -> u64 {
    let value = x.wrapping_mul(0x9e37_79b1_85eb_ca87) ^ y.wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    value.rotate_left(13) ^ x.wrapping_add(y << 7)
}

trait Mixer {
    fn mix(&self, x: u64, y: u64) -> u64;
}

struct RotMixer;

impl Mixer for RotMixer {
    fn mix(&self, x: u64, y: u64) -> u64 {
        protected_mix_rust(x, y)
    }
}

fn fib_recursive(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => fib_recursive(n - 1) + fib_recursive(n - 2),
    }
}

fn compute(iterations: u64) -> (u64, u64, usize) {
    let fib20 = fib_recursive(20);
    let secret = str::from_utf8(&RUST_VISIBLE_SECRET).expect("secret utf8");
    let mixer: &dyn Mixer = &RotMixer;
    let mut checksum = 0x0ddc_0ffe_eec0_ffee_u64;

    for i in 0..iterations {
        let mut values = [0u64; 9];
        for (idx, byte) in secret.as_bytes().iter().take(8).enumerate() {
            values[idx] = ((u64::from(*byte) + idx as u64 * 9 + i) % 97) + 1;
        }
        values[8] = (fib20 + i) % 97 + 1;
        values.sort_unstable();
        let local: u64 = values.iter().copied().sum();
        checksum ^= mixer.mix(local + fib20, values[8] + i);
        checksum = checksum.rotate_left(((i % 17) + 1) as u32);
        checksum = checksum.wrapping_add(values[0] + values.len() as u64);
    }

    (fib20, checksum, secret.len())
}

#[cfg(not(target_os = "android"))]
fn parse_iterations_std() -> u64 {
    std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1000)
}

#[cfg(not(target_os = "android"))]
fn main() {
    let (fib20, checksum, secret_len) = compute(parse_iterations_std());
    println!(
        "target_rust fib20={} checksum={} secret_len={}",
        fib20, checksum, secret_len
    );
}

#[cfg(target_os = "android")]
mod android_entry {
    use super::*;
    use core::arch::asm;
    use core::panic::PanicInfo;

    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        syscall_exit(1)
    }

    #[no_mangle]
    pub extern "C" fn rust_eh_personality() {}

    fn syscall_write(fd: usize, buf: *const u8, len: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc 0",
                in("x0") fd,
                in("x1") buf,
                in("x2") len,
                in("x8") 64usize,
                lateout("x0") ret,
                options(nostack),
            );
        }
        ret
    }

    fn syscall_exit(code: i32) -> ! {
        unsafe {
            asm!(
                "svc 0",
                in("x0") code as usize,
                in("x8") 93usize,
                options(noreturn),
            );
        }
    }

    fn append_bytes(buf: &mut [u8], cursor: &mut usize, bytes: &[u8]) {
        for byte in bytes {
            buf[*cursor] = *byte;
            *cursor += 1;
        }
    }

    fn append_u64(buf: &mut [u8], cursor: &mut usize, mut value: u64) {
        if value == 0 {
            buf[*cursor] = b'0';
            *cursor += 1;
            return;
        }
        let mut scratch = [0u8; 20];
        let mut digits = 0usize;
        while value > 0 {
            scratch[digits] = b'0' + (value % 10) as u8;
            value /= 10;
            digits += 1;
        }
        for idx in (0..digits).rev() {
            buf[*cursor] = scratch[idx];
            *cursor += 1;
        }
    }

    #[no_mangle]
    pub extern "C" fn _start() -> ! {
        let (fib20, checksum, secret_len) = compute(1000);
        let mut out = [0u8; 128];
        let mut cursor = 0usize;
        append_bytes(&mut out, &mut cursor, b"target_rust fib20=");
        append_u64(&mut out, &mut cursor, fib20);
        append_bytes(&mut out, &mut cursor, b" checksum=");
        append_u64(&mut out, &mut cursor, checksum);
        append_bytes(&mut out, &mut cursor, b" secret_len=");
        append_u64(&mut out, &mut cursor, secret_len as u64);
        append_bytes(&mut out, &mut cursor, b"\n");
        let _ = syscall_write(1, out.as_ptr(), cursor);
        syscall_exit(0)
    }
}
