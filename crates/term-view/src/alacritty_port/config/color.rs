use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize};

use alacritty_config_derive::ConfigDeserialize;

use crate::display::color::{CellRgb, Rgb};

#[derive(ConfigDeserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Colors {
    pub primary: PrimaryColors,
    pub cursor: InvertedCellColors,
    pub vi_mode_cursor: InvertedCellColors,
    pub selection: InvertedCellColors,
    pub normal: NormalColors,
    pub bright: BrightColors,
    pub dim: Option<DimColors>,
    pub indexed_colors: Vec<IndexedColor>,
    pub search: SearchColors,
    pub line_indicator: LineIndicatorColors,
    pub hints: HintColors,
    pub transparent_background_colors: bool,
    pub draw_bold_text_with_bright_colors: bool,
    footer_bar: BarColors,
}

impl Colors {
    pub fn footer_bar_foreground(&self) -> Rgb {
        self.footer_bar.foreground.unwrap_or(self.primary.background)
    }

    pub fn footer_bar_background(&self) -> Rgb {
        self.footer_bar.background.unwrap_or(self.primary.foreground)
    }
}

#[derive(ConfigDeserialize, Serialize, Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct LineIndicatorColors {
    pub foreground: Option<Rgb>,
    pub background: Option<Rgb>,
}

#[derive(ConfigDeserialize, Serialize, Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct HintColors {
    pub start: HintStartColors,
    pub end: HintEndColors,
}

#[derive(ConfigDeserialize, Serialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct HintStartColors {
    pub foreground: CellRgb,
    pub background: CellRgb,
}

impl Default for HintStartColors {
    fn default() -> Self {
        Self {
            foreground: CellRgb::Rgb(Rgb::new(0x18, 0x18, 0x18)),
            background: CellRgb::Rgb(Rgb::new(0xf4, 0xbf, 0x75)),
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct HintEndColors {
    pub foreground: CellRgb,
    pub background: CellRgb,
}

impl Default for HintEndColors {
    fn default() -> Self {
        Self {
            foreground: CellRgb::Rgb(Rgb::new(0x18, 0x18, 0x18)),
            background: CellRgb::Rgb(Rgb::new(0xac, 0x42, 0x42)),
        }
    }
}

#[derive(Deserialize, Serialize, Copy, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndexedColor {
    pub color: Rgb,

    index: ColorIndex,
}

impl IndexedColor {
    #[inline]
    pub fn index(&self) -> u8 {
        self.index.0
    }
}

#[derive(Serialize, Copy, Clone, Default, Debug, PartialEq, Eq)]
struct ColorIndex(u8);

impl<'de> Deserialize<'de> for ColorIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let index = u8::deserialize(deserializer)?;

        if index < 16 {
            Err(SerdeError::custom(
                "Config error: indexed_color's index is {}, but a value bigger than 15 was \
                 expected; ignoring setting",
            ))
        } else {
            Ok(Self(index))
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvertedCellColors {
    #[config(alias = "text")]
    pub foreground: CellRgb,
    #[config(alias = "cursor")]
    pub background: CellRgb,
}

impl Default for InvertedCellColors {
    fn default() -> Self {
        Self { foreground: CellRgb::CellBackground, background: CellRgb::CellForeground }
    }
}

#[derive(ConfigDeserialize, Serialize, Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct SearchColors {
    pub focused_match: FocusedMatchColors,
    pub matches: MatchColors,
}

#[derive(ConfigDeserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq)]
pub struct FocusedMatchColors {
    pub foreground: CellRgb,
    pub background: CellRgb,
}

impl Default for FocusedMatchColors {
    fn default() -> Self {
        Self {
            background: CellRgb::Rgb(Rgb::new(0xf4, 0xbf, 0x75)),
            foreground: CellRgb::Rgb(Rgb::new(0x18, 0x18, 0x18)),
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq)]
pub struct MatchColors {
    pub foreground: CellRgb,
    pub background: CellRgb,
}

impl Default for MatchColors {
    fn default() -> Self {
        Self {
            background: CellRgb::Rgb(Rgb::new(0xac, 0x42, 0x42)),
            foreground: CellRgb::Rgb(Rgb::new(0x18, 0x18, 0x18)),
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct BarColors {
    foreground: Option<Rgb>,
    background: Option<Rgb>,
}

#[derive(ConfigDeserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PrimaryColors {
    pub foreground: Rgb,
    pub background: Rgb,
    pub bright_foreground: Option<Rgb>,
    pub dim_foreground: Option<Rgb>,
}

impl Default for PrimaryColors {
    fn default() -> Self {
        PrimaryColors {
            background: Rgb::new(0x11, 0x13, 0x1a),
            foreground: Rgb::new(0xe7, 0xe1, 0xd8),
            bright_foreground: Default::default(),
            dim_foreground: Default::default(),
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NormalColors {
    pub black: Rgb,
    pub red: Rgb,
    pub green: Rgb,
    pub yellow: Rgb,
    pub blue: Rgb,
    pub magenta: Rgb,
    pub cyan: Rgb,
    pub white: Rgb,
}

impl Default for NormalColors {
    fn default() -> Self {
        NormalColors {
            black: Rgb::new(0x1d, 0x23, 0x2e),
            red: Rgb::new(0xed, 0x6f, 0x73),
            green: Rgb::new(0x8f, 0xc9, 0x91),
            yellow: Rgb::new(0xeb, 0xca, 0x8a),
            blue: Rgb::new(0x78, 0xa8, 0xff),
            magenta: Rgb::new(0xc7, 0x8c, 0xff),
            cyan: Rgb::new(0x6f, 0xd6, 0xcc),
            white: Rgb::new(0xe7, 0xe1, 0xd8),
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct BrightColors {
    pub black: Rgb,
    pub red: Rgb,
    pub green: Rgb,
    pub yellow: Rgb,
    pub blue: Rgb,
    pub magenta: Rgb,
    pub cyan: Rgb,
    pub white: Rgb,
}

impl Default for BrightColors {
    fn default() -> Self {
        BrightColors {
            black: Rgb::new(0x4a, 0x52, 0x66),
            red: Rgb::new(0xff, 0x89, 0x8d),
            green: Rgb::new(0xae, 0xe8, 0xaa),
            yellow: Rgb::new(0xff, 0xde, 0xa8),
            blue: Rgb::new(0x9b, 0xc5, 0xff),
            magenta: Rgb::new(0xdd, 0xa8, 0xff),
            cyan: Rgb::new(0x97, 0xe8, 0xe0),
            white: Rgb::new(0xf6, 0xef, 0xe8),
        }
    }
}

#[derive(ConfigDeserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DimColors {
    pub black: Rgb,
    pub red: Rgb,
    pub green: Rgb,
    pub yellow: Rgb,
    pub blue: Rgb,
    pub magenta: Rgb,
    pub cyan: Rgb,
    pub white: Rgb,
}

impl Default for DimColors {
    fn default() -> Self {
        DimColors {
            black: Rgb::new(0x16, 0x1b, 0x24),
            red: Rgb::new(0xb8, 0x50, 0x58),
            green: Rgb::new(0x6f, 0x94, 0x6c),
            yellow: Rgb::new(0xb7, 0x98, 0x5d),
            blue: Rgb::new(0x4e, 0x73, 0xa8),
            magenta: Rgb::new(0x8d, 0x6f, 0xb0),
            cyan: Rgb::new(0x5f, 0x9c, 0x97),
            white: Rgb::new(0x9f, 0xa7, 0xb4),
        }
    }
}
