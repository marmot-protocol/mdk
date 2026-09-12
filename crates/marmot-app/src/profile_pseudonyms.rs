//! Shared cosmetic display-pseudonym helpers.
//!
//! These names are presentation-only. They are not unique, anonymous, or a
//! security primitive. [`default_profile_pseudonym`] hashes the supplied
//! account-id text as UTF-8 without normalizing, decoding, trimming, or
//! validating it. Consumers that start from a scanned reference should call
//! [`crate::account_id_hex_from_ref`] first so the seed is the lowercase
//! canonical hex account id.

use rand::RngCore;
use sha2::{Digest, Sha256};

const DEFAULT_PROFILE_ADJECTIVES: &[&str] = &[
    "Agile", "Amber", "Angry", "Balanced", "Bold", "Brave", "Breezy", "Bright", "Brisk", "Bubbly",
    "Calm", "Caring", "Cheerful", "Clear", "Clever", "Coral", "Cosmic", "Cozy", "Crimson", "Crisp",
    "Curious", "Daring", "Dawn", "Deep", "Diamond", "Dreamy", "Eager", "Earnest", "Easy",
    "Electric", "Emerald", "Festive", "Fiery", "Fleet", "Forest", "Fresh", "Frosty", "Gentle",
    "Glad", "Golden", "Graceful", "Grand", "Grateful", "Green", "Happy", "Hardy", "Hearty",
    "Hidden", "Honest", "Hopeful", "Humble", "Indigo", "Ivory", "Jade", "Jolly", "Kind", "Lively",
    "Loyal", "Lucky", "Majestic", "Maple", "Mellow", "Merry", "Mighty", "Mindful", "Misty",
    "Modest", "Mossy", "Neat", "Nifty", "Nimble", "Noble", "Olive", "Open", "Patient", "Peaceful",
    "Plum", "Polar", "Proud", "Quiet", "Radiant", "Rapid", "Ready", "Restful", "Rosy", "Ruby",
    "Rustic", "Sage", "Scarlet", "Serene", "Sharp", "Shiny", "Silver", "Sincere", "Sky", "Smooth",
    "Solar", "Solid", "Spirited", "Spry", "Steady", "Stellar", "Stormy", "Sturdy", "Sunlit",
    "Sunny", "Swift", "Tame", "Tangy", "Tender", "Tidy", "Topaz", "Tranquil", "Trusty", "Twilight",
    "Upbeat", "Valiant", "Verdant", "Vivid", "Warm", "Willing", "Winsome", "Wise", "Witty",
    "Wondrous", "Woodland", "Young", "Zesty",
];
const DEFAULT_PROFILE_NOUNS: &[&str] = &[
    "Albatross",
    "Alpaca",
    "Ant",
    "Antelope",
    "Armadillo",
    "Badger",
    "Bat",
    "Bear",
    "Beaver",
    "Bee",
    "Bison",
    "Bluebird",
    "Bobcat",
    "Bullfrog",
    "Bumblebee",
    "Butterfly",
    "Camel",
    "Caribou",
    "Cat",
    "Caterpillar",
    "Cheetah",
    "Chickadee",
    "Chinchilla",
    "Chipmunk",
    "Cobra",
    "Condor",
    "Cougar",
    "Crab",
    "Crane",
    "Cricket",
    "Crow",
    "Deer",
    "Dingo",
    "Dolphin",
    "Dove",
    "Dragonfly",
    "Duck",
    "Eagle",
    "Egret",
    "Elephant",
    "Elk",
    "Falcon",
    "Fawn",
    "Ferret",
    "Finch",
    "Firefly",
    "Flamingo",
    "Flounder",
    "Fox",
    "Gazelle",
    "Gecko",
    "Giraffe",
    "Goat",
    "Goose",
    "Gopher",
    "Grouse",
    "Hare",
    "Hawk",
    "Hedgehog",
    "Heron",
    "Hippo",
    "Hornet",
    "Horse",
    "Hummingbird",
    "Ibex",
    "Iguana",
    "Jackal",
    "Jaguar",
    "Jay",
    "Kestrel",
    "Kingfisher",
    "Kiwi",
    "Koala",
    "Ladybug",
    "Lark",
    "Leopard",
    "Lion",
    "Llama",
    "Lynx",
    "Macaw",
    "Magpie",
    "Mallard",
    "Manatee",
    "Marmot",
    "Meerkat",
    "Mink",
    "Mole",
    "Mongoose",
    "Monkey",
    "Moose",
    "Mouse",
    "Narwhal",
    "Newt",
    "Nightingale",
    "Octopus",
    "Opossum",
    "Orca",
    "Oriole",
    "Ostrich",
    "Otter",
    "Owl",
    "Panda",
    "Parrot",
    "Peacock",
    "Pelican",
    "Penguin",
    "Pheasant",
    "Pigeon",
    "Pony",
    "Porcupine",
    "Puffin",
    "Quail",
    "Rabbit",
    "Raccoon",
    "Ram",
    "Raven",
    "Reindeer",
    "Rhino",
    "Roadrunner",
    "Robin",
    "Salamander",
    "Salmon",
    "Seal",
    "Swan",
    "Tiger",
    "Turtle",
    "Wolf",
    "Yak",
];

/// Deterministic adjective-noun display name for a canonical hex account id.
///
/// The seed is hashed as supplied UTF-8 text. This function does not
/// normalize, decode, trim, or validate `account_id_hex`. Signup and
/// fallback presentation keep this exact formula.
pub fn default_profile_pseudonym(account_id_hex: &str) -> String {
    let digest = Sha256::digest(account_id_hex.as_bytes());
    let adjective_index =
        u16::from_be_bytes([digest[0], digest[1]]) as usize % DEFAULT_PROFILE_ADJECTIVES.len();
    let noun_index =
        u16::from_be_bytes([digest[2], digest[3]]) as usize % DEFAULT_PROFILE_NOUNS.len();
    format!(
        "{} {}",
        DEFAULT_PROFILE_ADJECTIVES[adjective_index], DEFAULT_PROFILE_NOUNS[noun_index]
    )
}

/// Random cosmetic display name from the shared wordlists.
///
/// Draws 32 random bytes, lowercase-hex encodes them, and delegates to
/// [`default_profile_pseudonym`]. This does not generate a signing key or
/// create an account. Collisions are permitted.
pub fn random_profile_pseudonym() -> String {
    random_profile_pseudonym_with_rng(&mut rand::thread_rng())
}

fn random_profile_pseudonym_with_rng<R: RngCore>(rng: &mut R) -> String {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    default_profile_pseudonym(&hex::encode(bytes))
}

#[cfg(test)]
fn is_known_profile_pseudonym(name: &str) -> bool {
    let Some((adjective, noun)) = name.split_once(' ') else {
        return false;
    };
    if noun.contains(' ') {
        return false;
    }
    DEFAULT_PROFILE_ADJECTIVES.contains(&adjective) && DEFAULT_PROFILE_NOUNS.contains(&noun)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PROFILE_ADJECTIVES, DEFAULT_PROFILE_NOUNS, default_profile_pseudonym,
        is_known_profile_pseudonym, random_profile_pseudonym, random_profile_pseudonym_with_rng,
    };
    use rand::RngCore;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const BOOTSTRAP_ACCOUNT: &str =
        "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";

    #[test]
    fn default_profile_word_lists_keep_expected_shape() {
        assert_profile_word_list("adjectives", DEFAULT_PROFILE_ADJECTIVES);
        assert_profile_word_list("nouns", DEFAULT_PROFILE_NOUNS);
        assert_eq!(
            DEFAULT_PROFILE_ADJECTIVES.len() * DEFAULT_PROFILE_NOUNS.len(),
            16_384
        );
    }

    #[test]
    fn deterministic_names_match_frozen_vectors() {
        assert_eq!(default_profile_pseudonym(BOOTSTRAP_ACCOUNT), "Loyal Crane");
        assert_eq!(default_profile_pseudonym(&"0".repeat(64)), "Solar Mallard");
        assert_eq!(default_profile_pseudonym(&"bb".repeat(32)), "Wise Grouse");
    }

    #[test]
    fn deterministic_names_are_stable_and_hash_raw_utf8() {
        assert_eq!(
            default_profile_pseudonym(BOOTSTRAP_ACCOUNT),
            default_profile_pseudonym(BOOTSTRAP_ACCOUNT)
        );
        assert_ne!(
            default_profile_pseudonym(BOOTSTRAP_ACCOUNT),
            default_profile_pseudonym(&BOOTSTRAP_ACCOUNT.to_ascii_uppercase())
        );
        assert_ne!(
            default_profile_pseudonym(BOOTSTRAP_ACCOUNT),
            default_profile_pseudonym(&format!(" {BOOTSTRAP_ACCOUNT}"))
        );
        assert_eq!(
            default_profile_pseudonym("not-a-public-key"),
            default_profile_pseudonym("not-a-public-key")
        );
    }

    #[test]
    fn seeded_random_roll_delegates_to_the_deterministic_helper() {
        let mut rng = StdRng::seed_from_u64(959);
        let mut bytes = [0u8; 32];
        let mut expected_rng = StdRng::seed_from_u64(959);
        expected_rng.fill_bytes(&mut bytes);
        let name = random_profile_pseudonym_with_rng(&mut rng);
        assert_eq!(name, default_profile_pseudonym(&hex::encode(bytes)));
        assert!(is_known_profile_pseudonym(&name));
    }

    #[test]
    fn random_helper_smoke_stays_in_the_shared_tables() {
        let name = random_profile_pseudonym();
        assert!(is_known_profile_pseudonym(&name), "{name}");
    }

    #[test]
    fn seeded_corpus_covers_the_full_vocabulary() {
        let mut adjectives = std::collections::BTreeSet::new();
        let mut nouns = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for index in 0u32..4_096 {
            let name = default_profile_pseudonym(&format!("{index:064x}"));
            let (adjective, noun) = name.split_once(' ').expect("adjective noun");
            adjectives.insert(adjective.to_owned());
            nouns.insert(noun.to_owned());
            names.insert(name);
        }
        assert_eq!(adjectives.len(), DEFAULT_PROFILE_ADJECTIVES.len());
        assert_eq!(nouns.len(), DEFAULT_PROFILE_NOUNS.len());
        assert_eq!(names.len(), 3_663);
    }

    fn assert_profile_word_list(name: &str, words: &[&str]) {
        assert_eq!(words.len(), 128, "{name} should have 128 entries");
        for word in words {
            assert!(!word.is_empty(), "{name} should not contain empty words");
            let mut chars = word.chars();
            assert!(
                chars.next().is_some_and(|ch| ch.is_ascii_uppercase()),
                "{name} word should start uppercase: {word}"
            );
            assert!(
                chars.all(|ch| ch.is_ascii_lowercase()),
                "{name} word should be title-cased ASCII: {word}"
            );
        }
        for pair in words.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{name} should be sorted and unique: {} before {}",
                pair[0],
                pair[1]
            );
        }
    }
}
