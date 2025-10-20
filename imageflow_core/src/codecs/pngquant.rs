use super::Encoder;
use super::s::{EncoderPreset, EncodeResult};
use crate::io::IoProxy;

use imageflow_types::{Color, PixelFormat};
use crate::{Context, Result, ErrorKind};
use std::result::Result as StdResult;
use crate::io::IoProxyRef;
use std::slice;
use std::rc::Rc;
use std::cell::RefCell;
use std::os::raw::c_int;
use rgb::ComponentSlice;
use crate::codecs::lode;
use crate::graphics::bitmaps::BitmapKey;
use std::mem::MaybeUninit;
pub struct PngquantEncoder {
    liq: imagequant::Attributes,
    io: IoProxy,
    maximum_deflate: Option<bool>,
    matte: Option<Color>,
}

impl PngquantEncoder {
    pub(crate) fn create(c: &Context,io: IoProxy, speed: Option<u8>, quality: Option<u8>, minimum_quality: Option<u8>,
        maximum_deflate: Option<bool>, matte: Option<Color>) -> Result<Self> {
        if !c.enabled_codecs.encoders.contains(&crate::codecs::NamedEncoders::PngQuantEncoder){
            return Err(nerror!(ErrorKind::CodecDisabledError, "The PNGQuant encoder has been disabled"));
        }
        let mut liq = imagequant::new();
        if let Some(speed) = speed {
            liq.set_speed(speed.clamp(1, 10).into()).unwrap();
        }
        let min = minimum_quality.unwrap_or(0).clamp(0, 100);
        let max = quality.unwrap_or(100).clamp(0, 100);
        liq.set_quality(min, max).unwrap();

        Ok(PngquantEncoder {
            liq,
            io,
            maximum_deflate,
            matte,
        })
    }
}
impl PngquantEncoder{
    unsafe fn raw_byte_access(rgba: &[rgb::RGBA8]) -> &[u8] {
        use std::slice;
        slice::from_raw_parts(rgba.as_ptr() as *const u8, rgba.len() * 4)
    }
}
impl Encoder for PngquantEncoder {
    fn write_frame(&mut self, c: &Context, _preset: &EncoderPreset, bitmap_key: BitmapKey, decoder_io_ids: &[i32]) -> Result<EncodeResult> {

        let bitmaps = c.borrow_bitmaps()
            .map_err(|e| e.at(here!()))?;

        let mut bitmap = bitmaps.try_borrow_mut(bitmap_key)
            .map_err(|e| e.at(here!()))?;

        if self.matte.is_some() {
            bitmap.apply_matte(self.matte.clone().unwrap()).map_err(|e| e.at(here!()))?;
        }

        bitmap.get_window_u8().unwrap().normalize_unused_alpha()
        .map_err(|e| e.at(here!()))?;
        let mut window = bitmap.get_window_bgra32().unwrap();

        let (w,h) = window.size_usize();



        let error = {
            let mut img = unsafe {
                imagequant::Image::new_fn(&self.liq, |row: &mut [MaybeUninit<imagequant::RGBA>], row_index:usize| {
                    let from = window.row(row_index).unwrap();
                    from.iter().zip(row).for_each(|(from, to)| {
                        to.write(imagequant::RGBA {
                            r: from.r,
                            g: from.g,
                            b: from.b,
                            a: from.a,
                        });
                    });
                },w,h,0.0).map_err(|e| crate::FlowError::from(e).at(here!()))?
            };
            match self.liq.quantize(&mut img){
                Ok(mut res) => {
                    res.set_dithering_level(1.).unwrap();

                    let (pal, pixels) = res.remapped(&mut img).unwrap(); // could have alloc failure here, should map

                    lode::LodepngEncoder::write_png8(&mut self.io, &pal, &pixels, w, h, self.maximum_deflate)?;
                    None
                },
                Err(e) => Some(e)
            }
        };
        match error {
            Some(imagequant::liq_error::QualityTooLow) => {

                let (vec, w, h) = window.to_vec_rgba().map_err(|e| e.at(here!()))?;

                let slice_as_u8 = bytemuck::cast_slice::<rgb::RGBA8, u8>(vec.as_slice());


                lode::LodepngEncoder::write_png_auto_slice(&mut self.io, slice_as_u8, w, h, lodepng::ColorType::RGBA, self.maximum_deflate)
                .map_err(|e| e.at(here!()))?;
            }
            Some(err) => return Err(err)?,
            None => {}
        };


        Ok(EncodeResult {
            w: w as i32,
            h: h as i32,
            io_id: self.io.io_id(),
            bytes: ::imageflow_types::ResultBytes::Elsewhere,
            preferred_extension: "png".to_owned(),
            preferred_mime_type: "image/png".to_owned(),
        })

    }

    fn get_io(&self) -> Result<IoProxyRef> {
        Ok(IoProxyRef::Borrow(&self.io))
    }
}
