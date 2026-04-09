//! Fuzz target: decode arbitrary bytes + re-encode in a random format.
//!
//! Structured fuzzing varies the output format (JPEG/PNG/WebP/GIF) and
//! quality. Tests the full decode → encode path through C codecs including
//! pixel format conversion and encoder robustness with arbitrary pixels.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use imageflow_core::Context;
use imageflow_types as s;

#[derive(Debug, Arbitrary)]
struct TranscodeInput {
    format: u8,
    quality: u8,
    data: Vec<u8>,
}

fn limits() -> s::ExecutionSecurity {
    let mut sec = s::ExecutionSecurity::sane_defaults();
    let limit = Some(s::FrameSizeLimit { w: 4096, h: 4096, megapixels: 16.0 });
    sec.max_decode_size = limit;
    sec.max_frame_size = limit;
    sec.max_encode_size = limit;
    sec
}

fuzz_target!(|input: TranscodeInput| {
    if input.data.len() < 8 {
        return;
    }

    let Ok(mut ctx) = Context::create_can_panic() else { return; };
    ctx.configure_security(limits());
    if ctx.add_copied_input_buffer(0, &input.data).is_err() { return; }
    if ctx.add_output_buffer(1).is_err() { return; }

    let preset = match input.format % 4 {
        0 => s::EncoderPreset::Mozjpeg {
            quality: Some(input.quality.min(100)),
            progressive: Some(false),
            matte: None,
        },
        1 => s::EncoderPreset::Libpng {
            depth: None,
            matte: None,
            zlib_compression: None,
        },
        2 => s::EncoderPreset::WebPLossy {
            quality: (input.quality as f32).min(100.0),
        },
        _ => s::EncoderPreset::Gif,
    };

    let execute = s::Execute001 {
        framewise: s::Framewise::Steps(vec![
            s::Node::Decode { io_id: 0, commands: None },
            s::Node::Encode { io_id: 1, preset },
        ]),
        graph_recording: None,
        security: Some(limits()),
        job_options: None,
    };

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _ = ctx.execute_1(execute);
    }));
});
