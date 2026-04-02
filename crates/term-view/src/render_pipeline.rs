use std::cmp;

use alacritty_terminal::term::{MIN_COLUMNS, MIN_SCREEN_LINES};

/// Rendering backend selector for term-view.
///
/// The manual loop can drive either pipeline (or both in different windows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderPipeline {
    Egui,
    AlacrittyOpenGl,
}

/// Terminal size info directly adapted from Alacritty's display subsystem.
///
/// This keeps geometry semantics consistent across egui and OpenGL backends.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct SizeInfo {
    width: f32,
    height: f32,
    cell_width: f32,
    cell_height: f32,
    padding_x: f32,
    padding_y: f32,
    screen_lines: usize,
    columns: usize,
}

impl SizeInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        width: f32,
        height: f32,
        cell_width: f32,
        cell_height: f32,
        mut padding_x: f32,
        mut padding_y: f32,
        dynamic_padding: bool,
    ) -> Self {
        if dynamic_padding {
            padding_x = Self::dynamic_padding(padding_x.floor(), width, cell_width);
            padding_y = Self::dynamic_padding(padding_y.floor(), height, cell_height);
        }

        let lines = (height - 2.0 * padding_y) / cell_height;
        let screen_lines = cmp::max(lines as usize, MIN_SCREEN_LINES);

        let cols = (width - 2.0 * padding_x) / cell_width;
        let columns = cmp::max(cols as usize, MIN_COLUMNS);

        Self {
            width,
            height,
            cell_width,
            cell_height,
            padding_x: padding_x.floor(),
            padding_y: padding_y.floor(),
            screen_lines,
            columns,
        }
    }

    #[inline]
    pub fn width(&self) -> f32 {
        self.width
    }

    #[inline]
    pub fn height(&self) -> f32 {
        self.height
    }

    #[inline]
    pub fn cell_width(&self) -> f32 {
        self.cell_width
    }

    #[inline]
    pub fn cell_height(&self) -> f32 {
        self.cell_height
    }

    #[inline]
    pub fn padding_x(&self) -> f32 {
        self.padding_x
    }

    #[inline]
    pub fn padding_y(&self) -> f32 {
        self.padding_y
    }

    #[inline]
    pub fn screen_lines(&self) -> usize {
        self.screen_lines
    }

    #[inline]
    pub fn columns(&self) -> usize {
        self.columns
    }

    #[inline]
    fn dynamic_padding(base_padding: f32, dim: f32, cell_dim: f32) -> f32 {
        let free_space = (dim - 2.0 * base_padding).max(0.0);
        let cells = (free_space / cell_dim).floor();
        let used = cells * cell_dim;
        base_padding + (free_space - used) / 2.0
    }
}
