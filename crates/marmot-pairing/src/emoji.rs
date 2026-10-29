//! The 64-entry emoji table of Matrix's SAS `emoji` method, verbatim.
//!
//! Copied from the Matrix Specification's `data-definitions/sas-emoji.json`
//! (<https://github.com/matrix-org/matrix-spec>, commit
//! `7aaeac07608f97942eff88634a56b630a745ce56`): each entry's number, emoji,
//! English description and code points. Translated descriptions live in the
//! same Matrix file and are not copied here. Do not edit an entry: the table is
//! part of the pairing wire format.

/// One emoji of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SasEmoji {
    /// Its position in the table, `0..=63`: the 6-bit value that selects it.
    pub number: u8,
    /// The emoji itself, as the code points below.
    pub emoji: &'static str,
    /// Matrix's English description, for screen readers. Users compare the
    /// pictures, not the descriptions, which differ between languages.
    pub description: &'static str,
    /// The code points as Matrix writes them, such as `U+1F436`.
    pub unicode: &'static str,
}

/// The table, indexed by [`SasEmoji::number`].
pub const SAS_EMOJI: [SasEmoji; 64] = [
    SasEmoji {
        number: 0,
        emoji: "\u{1f436}",
        description: "Dog",
        unicode: "U+1F436",
    },
    SasEmoji {
        number: 1,
        emoji: "\u{1f431}",
        description: "Cat",
        unicode: "U+1F431",
    },
    SasEmoji {
        number: 2,
        emoji: "\u{1f981}",
        description: "Lion",
        unicode: "U+1F981",
    },
    SasEmoji {
        number: 3,
        emoji: "\u{1f40e}",
        description: "Horse",
        unicode: "U+1F40E",
    },
    SasEmoji {
        number: 4,
        emoji: "\u{1f984}",
        description: "Unicorn",
        unicode: "U+1F984",
    },
    SasEmoji {
        number: 5,
        emoji: "\u{1f437}",
        description: "Pig",
        unicode: "U+1F437",
    },
    SasEmoji {
        number: 6,
        emoji: "\u{1f418}",
        description: "Elephant",
        unicode: "U+1F418",
    },
    SasEmoji {
        number: 7,
        emoji: "\u{1f430}",
        description: "Rabbit",
        unicode: "U+1F430",
    },
    SasEmoji {
        number: 8,
        emoji: "\u{1f43c}",
        description: "Panda",
        unicode: "U+1F43C",
    },
    SasEmoji {
        number: 9,
        emoji: "\u{1f413}",
        description: "Rooster",
        unicode: "U+1F413",
    },
    SasEmoji {
        number: 10,
        emoji: "\u{1f427}",
        description: "Penguin",
        unicode: "U+1F427",
    },
    SasEmoji {
        number: 11,
        emoji: "\u{1f422}",
        description: "Turtle",
        unicode: "U+1F422",
    },
    SasEmoji {
        number: 12,
        emoji: "\u{1f41f}",
        description: "Fish",
        unicode: "U+1F41F",
    },
    SasEmoji {
        number: 13,
        emoji: "\u{1f419}",
        description: "Octopus",
        unicode: "U+1F419",
    },
    SasEmoji {
        number: 14,
        emoji: "\u{1f98b}",
        description: "Butterfly",
        unicode: "U+1F98B",
    },
    SasEmoji {
        number: 15,
        emoji: "\u{1f337}",
        description: "Flower",
        unicode: "U+1F337",
    },
    SasEmoji {
        number: 16,
        emoji: "\u{1f333}",
        description: "Tree",
        unicode: "U+1F333",
    },
    SasEmoji {
        number: 17,
        emoji: "\u{1f335}",
        description: "Cactus",
        unicode: "U+1F335",
    },
    SasEmoji {
        number: 18,
        emoji: "\u{1f344}",
        description: "Mushroom",
        unicode: "U+1F344",
    },
    SasEmoji {
        number: 19,
        emoji: "\u{1f30f}",
        description: "Globe",
        unicode: "U+1F30F",
    },
    SasEmoji {
        number: 20,
        emoji: "\u{1f319}",
        description: "Moon",
        unicode: "U+1F319",
    },
    SasEmoji {
        number: 21,
        emoji: "\u{2601}\u{fe0f}",
        description: "Cloud",
        unicode: "U+2601U+FE0F",
    },
    SasEmoji {
        number: 22,
        emoji: "\u{1f525}",
        description: "Fire",
        unicode: "U+1F525",
    },
    SasEmoji {
        number: 23,
        emoji: "\u{1f34c}",
        description: "Banana",
        unicode: "U+1F34C",
    },
    SasEmoji {
        number: 24,
        emoji: "\u{1f34e}",
        description: "Apple",
        unicode: "U+1F34E",
    },
    SasEmoji {
        number: 25,
        emoji: "\u{1f353}",
        description: "Strawberry",
        unicode: "U+1F353",
    },
    SasEmoji {
        number: 26,
        emoji: "\u{1f33d}",
        description: "Corn",
        unicode: "U+1F33D",
    },
    SasEmoji {
        number: 27,
        emoji: "\u{1f355}",
        description: "Pizza",
        unicode: "U+1F355",
    },
    SasEmoji {
        number: 28,
        emoji: "\u{1f382}",
        description: "Cake",
        unicode: "U+1F382",
    },
    SasEmoji {
        number: 29,
        emoji: "\u{2764}\u{fe0f}",
        description: "Heart",
        unicode: "U+2764U+FE0F",
    },
    SasEmoji {
        number: 30,
        emoji: "\u{1f600}",
        description: "Smiley",
        unicode: "U+1F600",
    },
    SasEmoji {
        number: 31,
        emoji: "\u{1f916}",
        description: "Robot",
        unicode: "U+1F916",
    },
    SasEmoji {
        number: 32,
        emoji: "\u{1f3a9}",
        description: "Hat",
        unicode: "U+1F3A9",
    },
    SasEmoji {
        number: 33,
        emoji: "\u{1f453}",
        description: "Glasses",
        unicode: "U+1F453",
    },
    SasEmoji {
        number: 34,
        emoji: "\u{1f527}",
        description: "Spanner",
        unicode: "U+1F527",
    },
    SasEmoji {
        number: 35,
        emoji: "\u{1f385}",
        description: "Santa",
        unicode: "U+1F385",
    },
    SasEmoji {
        number: 36,
        emoji: "\u{1f44d}",
        description: "Thumbs Up",
        unicode: "U+1F44D",
    },
    SasEmoji {
        number: 37,
        emoji: "\u{2602}\u{fe0f}",
        description: "Umbrella",
        unicode: "U+2602U+FE0F",
    },
    SasEmoji {
        number: 38,
        emoji: "\u{231b}",
        description: "Hourglass",
        unicode: "U+231B",
    },
    SasEmoji {
        number: 39,
        emoji: "\u{23f0}",
        description: "Clock",
        unicode: "U+23F0",
    },
    SasEmoji {
        number: 40,
        emoji: "\u{1f381}",
        description: "Gift",
        unicode: "U+1F381",
    },
    SasEmoji {
        number: 41,
        emoji: "\u{1f4a1}",
        description: "Light Bulb",
        unicode: "U+1F4A1",
    },
    SasEmoji {
        number: 42,
        emoji: "\u{1f4d5}",
        description: "Book",
        unicode: "U+1F4D5",
    },
    SasEmoji {
        number: 43,
        emoji: "\u{270f}\u{fe0f}",
        description: "Pencil",
        unicode: "U+270FU+FE0F",
    },
    SasEmoji {
        number: 44,
        emoji: "\u{1f4ce}",
        description: "Paperclip",
        unicode: "U+1F4CE",
    },
    SasEmoji {
        number: 45,
        emoji: "\u{2702}\u{fe0f}",
        description: "Scissors",
        unicode: "U+2702U+FE0F",
    },
    SasEmoji {
        number: 46,
        emoji: "\u{1f512}",
        description: "Lock",
        unicode: "U+1F512",
    },
    SasEmoji {
        number: 47,
        emoji: "\u{1f511}",
        description: "Key",
        unicode: "U+1F511",
    },
    SasEmoji {
        number: 48,
        emoji: "\u{1f528}",
        description: "Hammer",
        unicode: "U+1F528",
    },
    SasEmoji {
        number: 49,
        emoji: "\u{260e}\u{fe0f}",
        description: "Telephone",
        unicode: "U+260EU+FE0F",
    },
    SasEmoji {
        number: 50,
        emoji: "\u{1f3c1}",
        description: "Flag",
        unicode: "U+1F3C1",
    },
    SasEmoji {
        number: 51,
        emoji: "\u{1f682}",
        description: "Train",
        unicode: "U+1F682",
    },
    SasEmoji {
        number: 52,
        emoji: "\u{1f6b2}",
        description: "Bicycle",
        unicode: "U+1F6B2",
    },
    SasEmoji {
        number: 53,
        emoji: "\u{2708}\u{fe0f}",
        description: "Aeroplane",
        unicode: "U+2708U+FE0F",
    },
    SasEmoji {
        number: 54,
        emoji: "\u{1f680}",
        description: "Rocket",
        unicode: "U+1F680",
    },
    SasEmoji {
        number: 55,
        emoji: "\u{1f3c6}",
        description: "Trophy",
        unicode: "U+1F3C6",
    },
    SasEmoji {
        number: 56,
        emoji: "\u{26bd}",
        description: "Ball",
        unicode: "U+26BD",
    },
    SasEmoji {
        number: 57,
        emoji: "\u{1f3b8}",
        description: "Guitar",
        unicode: "U+1F3B8",
    },
    SasEmoji {
        number: 58,
        emoji: "\u{1f3ba}",
        description: "Trumpet",
        unicode: "U+1F3BA",
    },
    SasEmoji {
        number: 59,
        emoji: "\u{1f514}",
        description: "Bell",
        unicode: "U+1F514",
    },
    SasEmoji {
        number: 60,
        emoji: "\u{2693}",
        description: "Anchor",
        unicode: "U+2693",
    },
    SasEmoji {
        number: 61,
        emoji: "\u{1f3a7}",
        description: "Headphones",
        unicode: "U+1F3A7",
    },
    SasEmoji {
        number: 62,
        emoji: "\u{1f4c1}",
        description: "Folder",
        unicode: "U+1F4C1",
    },
    SasEmoji {
        number: 63,
        emoji: "\u{1f4cc}",
        description: "Pin",
        unicode: "U+1F4CC",
    },
];
