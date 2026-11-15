//! Exact renderer shared with host geometry tests. Both complete npubs are
//! paged before the existing three-page dwell/release gate permits a hold.
use crate::{layout::Layout, palette::WARN};
use embedded_graphics::{mono_font::MonoTextStyle, pixelcolor::Rgb565, prelude::*, text::Text};

#[allow(clippy::too_many_arguments)]
pub fn draw<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    action: &str,
    root_title: &str,
    root_npub: &str,
    target_npub: &str,
    remaining: u32,
    page: usize,
    armed: bool,
) {
    let size = display.bounding_box().size;
    let l = Layout::new(size.width as i32, size.height as i32);
    let style = MonoTextStyle::new(l.font_small(), WARN);
    let title = match page {
        0 => root_title,
        1 => "TARGET RAW NPUB",
        _ => action,
    };
    Text::new(title, Point::new(l.sx(2), l.sy(8)), style)
        .draw(display)
        .ok();
    let text = match page {
        0 => root_npub,
        1 => target_npub,
        _ => "File + same root\nNo app permissions\nNo overwrite",
    };
    let lines: Vec<&str> = if page < 2 {
        text.as_bytes()
            .chunks(18)
            .filter_map(|c| core::str::from_utf8(c).ok())
            .collect()
    } else {
        text.lines().collect()
    };
    for (i, line) in lines.iter().enumerate() {
        Text::new(line, Point::new(l.sx(2), l.sy(19 + i as i32 * 8)), style)
            .draw(display)
            .ok();
    }
    let hint = if armed {
        "Hold 5s to approve"
    } else {
        "Read all 3 pages"
    };
    Text::new(hint, Point::new(l.sx(2), l.sy(54)), style)
        .draw(display)
        .ok();
    Text::new(
        &format!("{}/3  {remaining}s", page + 1),
        Point::new(l.sx(2), l.sy(63)),
        style,
    )
    .draw(display)
    .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    struct CheckedCanvas {
        size: Size,
        pixels: BTreeSet<(i32, i32)>,
    }
    impl OriginDimensions for CheckedCanvas {
        fn size(&self) -> Size {
            self.size
        }
    }
    impl DrawTarget for CheckedCanvas {
        type Color = Rgb565;
        type Error = core::convert::Infallible;
        fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
            &mut self,
            pixels: I,
        ) -> Result<(), Self::Error> {
            for Pixel(p, _) in pixels {
                assert!(
                    self.bounding_box().contains(p),
                    "text clipped at {p:?} on {:?}",
                    self.size
                );
                assert!(
                    self.pixels.insert((p.x, p.y)),
                    "text overlapped at {p:?} on {:?}",
                    self.size
                );
            }
            Ok(())
        }
    }
    #[test]
    fn wrapped_card_shows_complete_npubs_without_clipping_or_overlap_on_every_panel() {
        let npub = "npub1".to_string() + &"q".repeat(58);
        for (w, h) in [(128, 64), (240, 135), (172, 320), (320, 172)] {
            for action in [
                "WRAP RAW ACCOUNT",
                "CHECK RAW ACCOUNT",
                "RESTORE RAW SLOT 7",
            ] {
                for page in 0..3 {
                    for armed in [false, true] {
                        let mut d = CheckedCanvas {
                            size: Size::new(w, h),
                            pixels: BTreeSet::new(),
                        };
                        draw(
                            &mut d,
                            action,
                            "ROOT 7 MODE 2",
                            &npub,
                            &npub,
                            60,
                            page,
                            armed,
                        );
                        assert!(!d.pixels.is_empty());
                    }
                }
            }
        }
    }
}
