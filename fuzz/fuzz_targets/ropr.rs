#![no_main]
use libfuzzer_sys::fuzz_target;

use std::{
	collections::HashMap,
	io::{Seek, SeekFrom, Write},
	os::unix::io::AsRawFd,
	path::Path,
};

fuzz_target!(|data: (&[u8], u8, u8)| {
	let mfd = match memfd::MemfdOptions::default().create("fuzz-file") {
		Ok(m) => m,
		Err(_) => return,
	};

	let fd = mfd.as_raw_fd();
	let filepath = format!("/proc/self/fd/{fd}");

	let mut file = mfd.into_file();
	if file.write_all(data.0).is_err() {
		println!("could not write to memfd file!");
		return;
	}

	if file.seek(SeekFrom::Start(0)).is_err() {
		println!("failed to seek!");
		return;
	}

	let _ = handle_file(filepath.as_str(), data.1, data.2);

	drop(file);
});

fn handle_file(
	path: impl AsRef<Path>,
	options: u8,
	max_instr: u8,
) -> Result<(), Box<dyn std::error::Error>> {
	let b = ropr::binary::Binary::new(&path)?;

	// option bits 0 and 1 select "raw"
	let raw = match options & 0b11 {
		0b00 => Some(true),
		0b01 => Some(false),
		_ => None,
	};
	let sections = b.sections(raw)?;

	// option bits 2-7 select flags
	let noisy = options & 0b10000000 > 0;
	let rop = options & 0b01000000 > 0;
	let sys = options & 0b00100000 > 0;
	let jop = options & 0b00010000 > 0;
	let stack_pivot = options & 0b00001000 > 0;
	let base_pivot = options & 0b00000100 > 0;

	let max_instructions_per_gadget = max_instr.saturating_add(1) as usize;

	let deduped = sections
		.iter()
		.filter_map(ropr::disassembler::Disassembly::new)
		.flat_map(|dis| {
			(0..dis.bytes().len())
				//.into_par_iter()
				.filter(|offset| dis.is_tail_at(*offset, rop, sys, jop, noisy))
				.flat_map(|tail| {
					dis.gadgets_from_tail(tail, max_instructions_per_gadget, noisy)
				})
				.collect::<Vec<_>>()
		})
		.collect::<HashMap<_, _>>();

	let _ = deduped
		.into_iter()
		.filter(|(g, _)| {
			let mut formatted = String::new();
			g.format_instruction(&mut formatted);
			true
		})
		.filter(|(g, _)| !stack_pivot | g.is_stack_pivot())
		.filter(|(g, _)| !base_pivot | g.is_base_pivot())
		.collect::<Vec<_>>();

	Ok(())
}
