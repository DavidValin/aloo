//! Fitting text into a column that is narrower than it is.

/// Keeps the *end* of `text`, marking what was dropped with a leading
/// ellipsis - what a path wants, since its last components say which
/// file this is and its first ones are the part every sibling row
/// repeats. `Photos/holiday/2019/norway/day-three/boat.jpg` in twenty
/// columns is `…day-three/boat.jpg`, not `Photos/holiday/2019…`.
///
/// Counts characters rather than bytes, so a path with accents is cut
/// where it looks cut. A `width` too small for even the ellipsis returns
/// as much of the tail as fits.
pub fn elide_start(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width <= 1 {
        return text.chars().skip(count.saturating_sub(width)).collect();
    }
    let tail: String = text.chars().skip(count - (width - 1)).collect();
    format!("\u{2026}{tail}")
}
