//! Turning an identity fingerprint into something two people can read to
//! each other.
//!
//! Comparing 64 hex characters over a phone call is the kind of thing
//! people do once and never again, so the fingerprint is rendered as eight
//! short words instead. Same idea as Signal's safety numbers and PGP's
//! word list: the point is not to add security - the fingerprint already
//! has it - but to make the check cheap enough that it actually happens.
//!
//! Eight words from a 256-word list is 64 bits of the fingerprint. That is
//! not the full 256, and deliberately so: it is what a person will really
//! read aloud, and forging a match still means finding a second identity
//! whose fingerprint collides in those 64 bits, which is far out of reach
//! of anyone who could not already do worse.
//!
//! The list is short, common, and phonetically distinct - words that
//! survive a bad line and an unfamiliar accent. No dependency; the whole
//! list is right here so a reader can check what it does.

/// 256 words, one per byte value. Order is load-bearing: changing it
/// changes every phrase this app has ever shown.
const WORDS: [&str; 256] = [
    "acid", "acorn", "album", "alien", "amber", "anchor", "angle", "apple", "april", "arctic",
    "arena", "armor", "arrow", "aspen", "atlas", "attic", "autumn", "bacon", "badge", "bagel",
    "baker", "balcony", "bamboo", "banjo", "barrel", "basil", "basket", "beacon", "beast", "beaver",
    "bench", "berry", "bicycle", "bishop", "bison", "black", "blanket", "blossom", "blue", "boiler",
    "bonus", "border", "bottle", "boulder", "bounce", "bracket", "branch", "brass", "bravo", "bread",
    "breeze", "bridge", "bright", "bronze", "brush", "bubble", "bucket", "buffalo", "bunker", "burger",
    "butter", "button", "cabin", "cable", "cactus", "camel", "candle", "canoe", "canvas", "canyon",
    "carbon", "cargo", "carpet", "carrot", "castle", "cattle", "cedar", "cement", "census", "cereal",
    "chalk", "chamber", "cheese", "cherry", "chess", "chimney", "circus", "citrus", "clay", "clever",
    "cliff", "clock", "cloud", "clover", "cobalt", "cocoa", "coffee", "collar", "column", "comet",
    "compass", "copper", "coral", "cotton", "cougar", "county", "cousin", "cover", "coyote", "crane",
    "crater", "crayon", "cream", "cricket", "crimson", "crystal", "curtain", "cushion", "cymbal", "daisy",
    "dancer", "danger", "dawn", "decade", "decimal", "denim", "desert", "diamond", "diesel", "dinner",
    "dolphin", "domain", "donkey", "double", "dragon", "drift", "drummer", "eagle", "early", "eclipse",
    "editor", "effort", "elbow", "elder", "electric", "elephant", "ember", "emerald", "empire", "energy",
    "engine", "envelope", "equal", "escape", "estate", "ethics", "evening", "exhibit", "expert", "fabric",
    "falcon", "family", "farmer", "feather", "fennel", "ferry", "fiber", "fiction", "fifty", "figure",
    "filter", "finger", "fire", "flame", "flask", "flint", "flower", "flute", "focus", "forest",
    "forge", "fortune", "fossil", "fountain", "fox", "frame", "freedom", "friend", "frost", "fuel",
    "future", "gadget", "galaxy", "gallon", "garden", "garlic", "gemini", "gentle", "geyser", "ginger",
    "glacier", "glass", "globe", "glove", "golden", "granite", "grape", "gravel", "green", "grotto",
    "guitar", "gypsum", "hamlet", "hammer", "harbor", "harvest", "hazel", "helmet", "herald", "hickory",
    "hollow", "honey", "horizon", "hunter", "hurdle", "iceberg", "igloo", "impact", "indigo", "insect",
    "iris", "island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jersey", "jewel", "jigsaw",
    "jockey", "jungle", "junior", "kernel", "kettle", "keyboard", "kidney", "kingdom", "kitten", "koala",
    "ladder", "lagoon", "lantern", "laptop", "laser", "lattice",
];

/// The eight-word phrase for a 32-byte identity fingerprint. Reading it to
/// the person on the other end, and hearing the same back, is what turns a
/// trust-on-first-use pin into a verified one.
pub fn phrase(fingerprint: &[u8; 32]) -> String {
    fingerprint[..8]
        .iter()
        .map(|b| WORDS[*b as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_has_no_duplicates() {
        let mut seen: Vec<&str> = WORDS.to_vec();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "two identities must never be able to read out the same word for different bytes"
        );
    }
}
