use std;
use crate::for_other_imageflow_crates::preludes::external_without_std::*;
use crate::ffi;
use crate::{Context, Result, JsonResponse};

use imageflow_types::collections::AddRemoveSet;
use crate::io::IoProxy;
use uuid::Uuid;
use imageflow_types::{IoDirection, PixelLayout};
use super::*;
use std::any::Any;
use std::rc::Rc;
use crate::io::IoProxyProxy;
use crate::io::IoProxyRef;
use rgb::alt::BGRA8;
use crate::graphics::bitmaps::{ColorSpace, BitmapCompositing};


extern crate jpeg_decoder as jpeg;


pub struct JpegDecoder{
    decoder:  jpeg::Decoder<IoProxy>,
    width: Option<i32>,
    height: Option<i32>,
    pixel_format: Option<jpeg::PixelFormat>
}

impl JpegDecoder {
    pub fn create(c: &Context, io: IoProxy, io_id: i32) -> Result<JpegDecoder> {

        let decoder =  jpeg::Decoder::new(io);

        Ok(JpegDecoder{
            decoder,
            width: None,
            height: None,
            pixel_format: None
        })
    }
}


impl Decoder for JpegDecoder {
    fn initialize(&mut self, c: &Context) -> Result<()> {
        Ok(())
    }

    fn get_scaled_image_info(&mut self, c: &Context) -> Result<s::ImageInfo>{
        self.get_unscaled_image_info(c)
    }

    fn get_unscaled_image_info(&mut self, c: &Context) -> Result<s::ImageInfo> {

        self.decoder.read_info()?;
        let info = self.decoder.info().expect("error handling not yet implemented for jpeg");

        self.width = Some( i32::from(info.width));
        self.height = Some( i32::from(info.height));
        self.pixel_format = Some(info.pixel_format);


        Ok(s::ImageInfo {
            frame_decodes_into: s::PixelFormat::Bgra32,
            image_width: i32::from(info.width),
            image_height: i32::from(info.height),
            preferred_mime_type: "image/jpeg".to_owned(),
            preferred_extension: "jpg".to_owned(),
            lossless: false,
            multiple_frames: false
        })
    }

    //TODO! Support exif rotation
    fn get_exif_rotation_flag(&mut self, c: &Context) -> Result<Option<i32>> {
        Ok(None)
    }

    fn tell_decoder(&mut self, c: &Context, tell: s::DecoderCommand) -> Result<()> {
        Ok(())
    }

    fn read_frame(&mut self, c: &Context) -> Result<BitmapKey> {

        if self.width.is_none() {
            let _ = self.get_scaled_image_info(c)?;
        }
        let pixels = self.decoder.decode()?;

        //TODO! Support color profiles


        let w = self.width.unwrap();
        let h = self.height.unwrap();

        let bitmap_key = c.bitmaps.try_borrow_mut()
            .map_err(|e| nerror!(ErrorKind::FailedBorrow, "{:?}", e))?
            .create_bitmap_u8(w as u32,
                                h as u32,
                                PixelLayout::BGRA,
                                false,
                                false,
                                ColorSpace::StandardRGB,
                                BitmapCompositing::ReplaceSelf)
            .map_err(|e| e.at(here!()))?;

        let bitmaps = c.borrow_bitmaps()
            .map_err(|e| e.at(here!()))?;
        let mut bitmap = bitmaps.try_borrow_mut(bitmap_key)
            .map_err(|e| e.at(here!()))?;


        let mut window = bitmap.get_window_u8().unwrap();
        let (w, h) = window.size_usize();
        let stride = window.t_stride();

        //TODO: Shouldn't this be Bgr24
        match self.pixel_format.unwrap(){
            jpeg::PixelFormat::RGB24 => {
                let from_stride = w * 3;
                for mut line in window.scanlines_bgra().unwrap(){
                    let from_slice = &pixels[line.y() * from_stride..line.y() * from_stride + from_stride];
                    if from_slice.len() * 3 != line.row().len() {
                        panic!("from_slice.len() * 3 != line.row().len()");
                    }
                    from_slice.chunks_exact(3).zip(line.row_mut()).for_each(|(from, to)| {
                        to.r = from[0];
                        to.b = from[1];
                        to.g = from[2];
                    });
                }
            },
            jpeg::PixelFormat::L8 => {
                let from_stride = w;
                for mut line in window.scanlines_bgra().unwrap(){
                    let from_slice = &pixels[line.y() * from_stride..line.y() * from_stride + from_stride];
                    if from_slice.len() != line.row().len() {
                        panic!("from_slice.len() != line.row().len()");
                    }
                    from_slice.iter().zip(line.row_mut()).for_each(|(from, to)| {
                        *to = BGRA8{r: *from, g: *from, b: *from, a: 255};
                    });
                }
            }

            _ => {
                panic!("Unsupported jpeg type (grayscale or CMYK")
            }
        }
        Ok(bitmap_key)
    }
    fn has_more_frames(&mut self) -> Result<bool> {
        Ok(false)
    }
    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}
