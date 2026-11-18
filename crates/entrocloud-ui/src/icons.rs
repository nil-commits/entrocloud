//! Crisp anti-aliased vector icon painter (`egui::Painter` shapes, ZERO Unicode emojis or dingbats).

use std::f32::consts::{FRAC_PI_2, PI, TAU};

use eframe::egui::epaint::PathShape;
use eframe::egui::{self, Color32, Pos2, Rect, Rounding, Shape, Stroke, Vec2};

/// Vector icons painted cleanly at any DPI without relying on font emoji glyphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Icon {
    BrandShieldCloud,
    HomeBackups,
    Folder,
    FolderOpen,
    File,
    FileText,
    Cloud,
    CloudPlus,
    HardDrive,
    ShareLink,
    Users,
    Settings,
    Lock,
    Unlock,
    Plus,
    Upload,
    Download,
    Search,
    Grid,
    List,
    Pin,
    Check,
    Alert,
    Refresh,
    ExternalLink,
    Trash,
    Edit,
    Play,
    Pause,
    Stop,
    Sun,
    Moon,
    Eye,
    EyeOff,
    Copy,
    ChevronRight,
    ArrowLeft,
    Sparkles,
    BookOpen,
    Close,
    MoreHorizontal,
    SortAsc,
    SortDesc,
}

/// Paints the full-color rounded EntroCloud brand mark (`#007D78` badge + `#2DD4BF` accent + white cloud).
pub fn paint_brand_mark(painter: &egui::Painter, rect: Rect) {
    let side = rect.width().min(rect.height());
    let sq = Rect::from_center_size(rect.center(), Vec2::splat(side));
    let rounding = Rounding::same((side * 0.26).clamp(5.0, 12.0));

    painter.rect_filled(sq, rounding, Color32::from_rgb(0x00, 0x7D, 0x78));
    painter.rect_stroke(
        sq.shrink(0.5),
        rounding,
        Stroke::new(1.2, Color32::from_rgb(0x2D, 0xD4, 0xBF)),
    );

    let inner = sq.shrink(side * 0.18);
    paint_icon(painter, inner, Icon::BrandShieldCloud, Color32::WHITE);
}

/// Paints a crisp anti-aliased vector [`Icon`] inside `rect` using `color`.
pub fn paint_icon(painter: &egui::Painter, rect: Rect, icon: Icon, color: Color32) {
    let side = rect.width().min(rect.height()).max(4.0);
    let box_rect = Rect::from_center_size(rect.center(), Vec2::splat(side));
    let sw = (side * 0.095).clamp(1.35, 2.25);
    let stroke = Stroke::new(sw, color);

    // Maps normalized 24x24 icon coordinates into `box_rect`.
    let pt = |x: f32, y: f32| -> Pos2 {
        Pos2::new(
            box_rect.left() + (x / 24.0) * side,
            box_rect.top() + (y / 24.0) * side,
        )
    };
    let sc = |v: f32| -> f32 { (v / 24.0) * side };

    match icon {
        Icon::BrandShieldCloud => {
            // Shield outline + crisp cloud inside
            let shield = vec![
                pt(12.0, 2.2),
                pt(20.0, 5.4),
                pt(20.0, 11.6),
                pt(17.4, 17.4),
                pt(12.0, 21.6),
                pt(6.6, 17.4),
                pt(4.0, 11.6),
                pt(4.0, 5.4),
            ];
            painter.add(Shape::Path(PathShape::closed_line(shield, stroke)));
            let cloud = cloud_outline_points(&pt, 12.0, 12.3, 0.58);
            painter.add(Shape::Path(PathShape::closed_line(
                cloud,
                Stroke::new((sw * 0.88).max(1.2), color),
            )));
        }
        Icon::HomeBackups => {
            // Layered archive/backup vault box with upward check/sync feel
            let r = Rect::from_min_max(pt(3.5, 6.5), pt(20.5, 19.5));
            painter.rect_stroke(r, Rounding::same(sc(2.4)), stroke);
            painter.line_segment([pt(6.5, 3.5), pt(17.5, 3.5)], stroke);
            painter.line_segment([pt(3.8, 11.0), pt(20.2, 11.0)], stroke);
            let check = vec![pt(9.2, 15.1), pt(11.3, 17.1), pt(15.2, 13.3)];
            painter.add(Shape::Path(PathShape::line(check, stroke)));
        }
        Icon::Folder => {
            let pts = vec![
                pt(3.0, 6.5),
                pt(9.2, 6.5),
                pt(11.4, 8.8),
                pt(21.0, 8.8),
                pt(21.0, 19.2),
                pt(3.0, 19.2),
            ];
            painter.add(Shape::Path(PathShape::closed_line(pts, stroke)));
        }
        Icon::FolderOpen => {
            let back = vec![
                pt(3.0, 18.8),
                pt(3.0, 6.2),
                pt(9.0, 6.2),
                pt(11.2, 8.4),
                pt(19.5, 8.4),
                pt(19.5, 11.5),
            ];
            painter.add(Shape::Path(PathShape::line(back, stroke)));
            let flap = vec![
                pt(3.0, 18.8),
                pt(5.6, 11.5),
                pt(21.4, 11.5),
                pt(18.8, 18.8),
            ];
            painter.add(Shape::Path(PathShape::closed_line(flap, stroke)));
        }
        Icon::File => {
            let doc = vec![
                pt(6.0, 3.2),
                pt(14.2, 3.2),
                pt(18.5, 7.5),
                pt(18.5, 20.8),
                pt(6.0, 20.8),
            ];
            painter.add(Shape::Path(PathShape::closed_line(doc, stroke)));
            let fold = vec![pt(14.0, 3.4), pt(14.0, 7.8), pt(18.3, 7.8)];
            painter.add(Shape::Path(PathShape::line(fold, stroke)));
        }
        Icon::FileText => {
            paint_icon(painter, box_rect, Icon::File, color);
            painter.line_segment([pt(8.8, 11.6), pt(15.6, 11.6)], stroke);
            painter.line_segment([pt(8.8, 14.8), pt(15.6, 14.8)], stroke);
            painter.line_segment([pt(8.8, 17.8), pt(13.0, 17.8)], stroke);
        }
        Icon::Cloud => {
            let pts = cloud_outline_points(&pt, 12.0, 13.0, 1.0);
            painter.add(Shape::Path(PathShape::closed_line(pts, stroke)));
        }
        Icon::CloudPlus => {
            let pts = cloud_outline_points(&pt, 11.4, 12.4, 0.92);
            painter.add(Shape::Path(PathShape::closed_line(pts, stroke)));
            painter.line_segment([pt(18.5, 14.5), pt(18.5, 20.5)], stroke);
            painter.line_segment([pt(15.5, 17.5), pt(21.5, 17.5)], stroke);
        }
        Icon::HardDrive => {
            let r = Rect::from_min_max(pt(3.0, 6.0), pt(21.0, 18.5));
            painter.rect_stroke(r, Rounding::same(sc(2.4)), stroke);
            painter.line_segment([pt(3.2, 13.5), pt(20.8, 13.5)], stroke);
            painter.circle_filled(pt(7.0, 16.0), sc(1.15), color);
            painter.circle_filled(pt(10.5, 16.0), sc(1.15), color);
        }
        Icon::ShareLink => {
            // Clean chain link / share nodes
            painter.circle_stroke(pt(18.0, 5.5), sc(2.6), stroke);
            painter.circle_stroke(pt(6.0, 12.0), sc(2.6), stroke);
            painter.circle_stroke(pt(18.0, 18.5), sc(2.6), stroke);
            painter.line_segment([pt(8.4, 10.7), pt(15.6, 6.8)], stroke);
            painter.line_segment([pt(8.4, 13.3), pt(15.6, 17.2)], stroke);
        }
        Icon::Users => {
            painter.circle_stroke(pt(9.2, 8.2), sc(3.1), stroke);
            let body1 = arc_points(pt(9.2, 19.2), sc(5.4), PI, TAU, 12);
            painter.add(Shape::Path(PathShape::line(body1, stroke)));
            let head2 = arc_points(pt(15.8, 8.4), sc(2.6), -FRAC_PI_2 * 0.8, FRAC_PI_2 * 0.8, 8);
            painter.add(Shape::Path(PathShape::line(head2, stroke)));
            let body2 = arc_points(pt(15.8, 19.2), sc(4.4), PI * 1.25, TAU, 8);
            painter.add(Shape::Path(PathShape::line(body2, stroke)));
        }
        Icon::Settings => {
            painter.circle_stroke(pt(12.0, 12.0), sc(3.2), stroke);
            painter.circle_stroke(pt(12.0, 12.0), sc(7.2), stroke);
            for i in 0..8 {
                let ang = (i as f32) * (TAU / 8.0);
                let p0 = Pos2::new(
                    pt(12.0, 12.0).x + ang.cos() * sc(7.2),
                    pt(12.0, 12.0).y + ang.sin() * sc(7.2),
                );
                let p1 = Pos2::new(
                    pt(12.0, 12.0).x + ang.cos() * sc(9.4),
                    pt(12.0, 12.0).y + ang.sin() * sc(9.4),
                );
                painter.line_segment([p0, p1], stroke);
            }
        }
        Icon::Lock => {
            let body = Rect::from_min_max(pt(5.2, 10.8), pt(18.8, 20.5));
            painter.rect_stroke(body, Rounding::same(sc(2.2)), stroke);
            let mut shackle = Vec::with_capacity(14);
            shackle.push(pt(8.2, 10.8));
            shackle.extend(arc_points(pt(12.0, 7.6), sc(3.8), PI, TAU, 12));
            shackle.push(pt(15.8, 10.8));
            painter.add(Shape::Path(PathShape::line(shackle, stroke)));
            painter.circle_filled(pt(12.0, 15.4), sc(1.25), color);
        }
        Icon::Unlock => {
            let body = Rect::from_min_max(pt(5.2, 10.8), pt(18.8, 20.5));
            painter.rect_stroke(body, Rounding::same(sc(2.2)), stroke);
            let mut shackle = Vec::with_capacity(14);
            shackle.push(pt(8.2, 10.8));
            shackle.extend(arc_points(pt(12.0, 7.2), sc(3.8), PI, TAU - 0.55, 10));
            painter.add(Shape::Path(PathShape::line(shackle, stroke)));
            painter.circle_filled(pt(12.0, 15.4), sc(1.25), color);
        }
        Icon::Plus => {
            painter.line_segment([pt(12.0, 5.0), pt(12.0, 19.0)], stroke);
            painter.line_segment([pt(5.0, 12.0), pt(19.0, 12.0)], stroke);
        }
        Icon::Upload => {
            painter.line_segment([pt(12.0, 15.5), pt(12.0, 4.5)], stroke);
            let arrow = vec![pt(7.5, 9.0), pt(12.0, 4.5), pt(16.5, 9.0)];
            painter.add(Shape::Path(PathShape::line(arrow, stroke)));
            let tray = vec![pt(4.5, 15.5), pt(4.5, 19.5), pt(19.5, 19.5), pt(19.5, 15.5)];
            painter.add(Shape::Path(PathShape::line(tray, stroke)));
        }
        Icon::Download => {
            painter.line_segment([pt(12.0, 4.5), pt(12.0, 15.2)], stroke);
            let arrow = vec![pt(7.5, 10.8), pt(12.0, 15.3), pt(16.5, 10.8)];
            painter.add(Shape::Path(PathShape::line(arrow, stroke)));
            let tray = vec![pt(4.5, 15.8), pt(4.5, 19.5), pt(19.5, 19.5), pt(19.5, 15.8)];
            painter.add(Shape::Path(PathShape::line(tray, stroke)));
        }
        Icon::Search => {
            painter.circle_stroke(pt(10.6, 10.6), sc(6.2), stroke);
            painter.line_segment([pt(15.2, 15.2), pt(20.2, 20.2)], stroke);
        }
        Icon::Grid => {
            for (x0, y0) in [(4.0, 4.0), (13.4, 4.0), (4.0, 13.4), (13.4, 13.4)] {
                let r = Rect::from_min_max(pt(x0, y0), pt(x0 + 6.6, y0 + 6.6));
                painter.rect_stroke(r, Rounding::same(sc(1.4)), stroke);
            }
        }
        Icon::List => {
            for y in [6.5, 12.0, 17.5] {
                painter.circle_filled(pt(5.0, y), sc(1.15), color);
                painter.line_segment([pt(8.6, y), pt(20.0, y)], stroke);
            }
        }
        Icon::Pin => {
            let body = vec![
                pt(9.0, 4.2),
                pt(15.0, 4.2),
                pt(16.5, 12.2),
                pt(7.5, 12.2),
            ];
            painter.add(Shape::Path(PathShape::closed_line(body, stroke)));
            painter.line_segment([pt(5.8, 12.2), pt(18.2, 12.2)], stroke);
            painter.line_segment([pt(12.0, 12.2), pt(12.0, 20.2)], stroke);
        }
        Icon::Check => {
            let pts = vec![pt(4.8, 12.6), pt(9.8, 17.6), pt(19.4, 6.8)];
            painter.add(Shape::Path(PathShape::line(pts, stroke)));
        }
        Icon::Alert => {
            let tri = vec![pt(12.0, 3.8), pt(21.0, 19.5), pt(3.0, 19.5)];
            painter.add(Shape::Path(PathShape::closed_line(tri, stroke)));
            painter.line_segment([pt(12.0, 9.6), pt(12.0, 14.2)], stroke);
            painter.circle_filled(pt(12.0, 17.1), sc(1.05), color);
        }
        Icon::Refresh => {
            let arc1 = arc_points(pt(12.0, 12.0), sc(7.2), -PI * 0.82, PI * 0.05, 14);
            painter.add(Shape::Path(PathShape::line(arc1, stroke)));
            let head1 = vec![pt(16.4, 7.8), pt(19.4, 11.4), pt(15.2, 12.2)];
            painter.add(Shape::Path(PathShape::line(head1, stroke)));

            let arc2 = arc_points(pt(12.0, 12.0), sc(7.2), PI * 0.18, PI * 1.05, 14);
            painter.add(Shape::Path(PathShape::line(arc2, stroke)));
            let head2 = vec![pt(7.6, 16.2), pt(4.6, 12.6), pt(8.8, 11.8)];
            painter.add(Shape::Path(PathShape::line(head2, stroke)));
        }
        Icon::ExternalLink => {
            let box_pts = vec![
                pt(13.0, 5.0),
                pt(5.0, 5.0),
                pt(5.0, 19.0),
                pt(19.0, 19.0),
                pt(19.0, 11.0),
            ];
            painter.add(Shape::Path(PathShape::line(box_pts, stroke)));
            painter.line_segment([pt(11.0, 13.0), pt(19.8, 4.2)], stroke);
            let arrow = vec![pt(14.8, 4.2), pt(19.8, 4.2), pt(19.8, 9.2)];
            painter.add(Shape::Path(PathShape::line(arrow, stroke)));
        }
        Icon::Trash => {
            painter.line_segment([pt(4.2, 6.8), pt(19.8, 6.8)], stroke);
            let cap = vec![pt(9.0, 6.8), pt(9.0, 4.2), pt(15.0, 4.2), pt(15.0, 6.8)];
            painter.add(Shape::Path(PathShape::line(cap, stroke)));
            let bin = vec![
                pt(6.2, 6.8),
                pt(7.2, 20.0),
                pt(16.8, 20.0),
                pt(17.8, 6.8),
            ];
            painter.add(Shape::Path(PathShape::line(bin, stroke)));
            painter.line_segment([pt(10.2, 10.5), pt(10.2, 16.8)], stroke);
            painter.line_segment([pt(13.8, 10.5), pt(13.8, 16.8)], stroke);
        }
        Icon::Edit => {
            let pen = vec![
                pt(15.8, 4.2),
                pt(19.8, 8.2),
                pt(8.8, 19.2),
                pt(4.2, 19.8),
                pt(4.8, 15.2),
            ];
            painter.add(Shape::Path(PathShape::closed_line(pen, stroke)));
            painter.line_segment([pt(13.6, 6.4), pt(17.6, 10.4)], stroke);
        }
        Icon::Play => {
            let tri = vec![pt(7.0, 4.8), pt(19.2, 12.0), pt(7.0, 19.2)];
            painter.add(Shape::Path(PathShape::convex_polygon(
                tri,
                color,
                Stroke::NONE,
            )));
        }
        Icon::Pause => {
            let r1 = Rect::from_min_max(pt(6.5, 5.0), pt(10.2, 19.0));
            let r2 = Rect::from_min_max(pt(13.8, 5.0), pt(17.5, 19.0));
            painter.rect_filled(r1, Rounding::same(sc(1.0)), color);
            painter.rect_filled(r2, Rounding::same(sc(1.0)), color);
        }
        Icon::Stop => {
            let r = Rect::from_min_max(pt(6.0, 6.0), pt(18.0, 18.0));
            painter.rect_filled(r, Rounding::same(sc(1.8)), color);
        }
        Icon::Sun => {
            painter.circle_stroke(pt(12.0, 12.0), sc(4.2), stroke);
            for i in 0..8 {
                let ang = (i as f32) * (TAU / 8.0);
                let c = pt(12.0, 12.0);
                let p0 = Pos2::new(c.x + ang.cos() * sc(6.5), c.y + ang.sin() * sc(6.5));
                let p1 = Pos2::new(c.x + ang.cos() * sc(9.2), c.y + ang.sin() * sc(9.2));
                painter.line_segment([p0, p1], stroke);
            }
        }
        Icon::Moon => {
            let outer = arc_points(pt(12.5, 12.0), sc(7.2), PI * 0.32, PI * 1.68, 16);
            let inner = arc_points(pt(15.6, 9.6), sc(5.8), PI * 1.48, PI * 0.56, 14);
            let mut crescent = outer;
            crescent.extend(inner.into_iter().rev());
            painter.add(Shape::Path(PathShape::closed_line(crescent, stroke)));
        }
        Icon::Eye => {
            let mut top = Vec::with_capacity(13);
            let mut bot = Vec::with_capacity(13);
            for i in 0..=12 {
                let t = (i as f32) / 12.0;
                let x = 2.8 + t * 18.4;
                let h = (t * PI).sin() * 5.6;
                top.push(pt(x, 12.0 - h));
                bot.push(pt(x, 12.0 + h));
            }
            painter.add(Shape::Path(PathShape::line(top, stroke)));
            painter.add(Shape::Path(PathShape::line(bot, stroke)));
            painter.circle_stroke(pt(12.0, 12.0), sc(2.6), stroke);
        }
        Icon::EyeOff => {
            paint_icon(painter, box_rect, Icon::Eye, color);
            painter.line_segment([pt(4.0, 4.0), pt(20.0, 20.0)], stroke);
        }
        Icon::Copy => {
            let front = Rect::from_min_max(pt(8.5, 8.5), pt(19.8, 19.8));
            painter.rect_stroke(front, Rounding::same(sc(2.0)), stroke);
            let back = vec![
                pt(15.5, 8.5),
                pt(15.5, 4.2),
                pt(4.2, 4.2),
                pt(4.2, 15.5),
                pt(8.5, 15.5),
            ];
            painter.add(Shape::Path(PathShape::line(back, stroke)));
        }
        Icon::ChevronRight => {
            let pts = vec![pt(9.0, 5.5), pt(15.5, 12.0), pt(9.0, 18.5)];
            painter.add(Shape::Path(PathShape::line(pts, stroke)));
        }
        Icon::ArrowLeft => {
            painter.line_segment([pt(19.5, 12.0), pt(5.0, 12.0)], stroke);
            let head = vec![pt(10.8, 6.2), pt(5.0, 12.0), pt(10.8, 17.8)];
            painter.add(Shape::Path(PathShape::line(head, stroke)));
        }
        Icon::Sparkles => {
            let star = vec![
                pt(12.0, 3.0),
                pt(14.2, 9.8),
                pt(21.0, 12.0),
                pt(14.2, 14.2),
                pt(12.0, 21.0),
                pt(9.8, 14.2),
                pt(3.0, 12.0),
                pt(9.8, 9.8),
            ];
            painter.add(Shape::Path(PathShape::closed_line(star, stroke)));
        }
        Icon::BookOpen => {
            let left_page = vec![
                pt(12.0, 6.5),
                pt(8.2, 5.2),
                pt(3.2, 5.6),
                pt(3.2, 18.4),
                pt(8.2, 18.0),
                pt(12.0, 19.4),
            ];
            let right_page = vec![
                pt(12.0, 6.5),
                pt(15.8, 5.2),
                pt(20.8, 5.6),
                pt(20.8, 18.4),
                pt(15.8, 18.0),
                pt(12.0, 19.4),
            ];
            painter.add(Shape::Path(PathShape::line(left_page, stroke)));
            painter.add(Shape::Path(PathShape::line(right_page, stroke)));
            painter.line_segment([pt(12.0, 6.5), pt(12.0, 19.4)], stroke);
        }
        Icon::Close => {
            painter.line_segment([pt(6.0, 6.0), pt(18.0, 18.0)], stroke);
            painter.line_segment([pt(18.0, 6.0), pt(6.0, 18.0)], stroke);
        }
        Icon::MoreHorizontal => {
            for x in [6.0, 12.0, 18.0] {
                painter.circle_filled(pt(x, 12.0), sc(1.45), color);
            }
        }
        Icon::SortAsc => {
            let pts = vec![pt(7.0, 15.0), pt(12.0, 9.0), pt(17.0, 15.0)];
            painter.add(Shape::Path(PathShape::line(pts, stroke)));
        }
        Icon::SortDesc => {
            let pts = vec![pt(7.0, 9.0), pt(12.0, 15.0), pt(17.0, 9.0)];
            painter.add(Shape::Path(PathShape::line(pts, stroke)));
        }
    }
}

fn arc_points(center: Pos2, radius: f32, start_ang: f32, end_ang: f32, steps: usize) -> Vec<Pos2> {
    let n = steps.max(2);
    let mut out = Vec::with_capacity(n + 1);
    for i in 0..=n {
        let t = (i as f32) / (n as f32);
        let ang = start_ang + (end_ang - start_ang) * t;
        out.push(Pos2::new(
            center.x + ang.cos() * radius,
            center.y + ang.sin() * radius,
        ));
    }
    out
}

fn cloud_outline_points(
    pt: &dyn Fn(f32, f32) -> Pos2,
    cx: f32,
    cy: f32,
    scale: f32,
) -> Vec<Pos2> {
    // Clean smooth cloud contour around `(cx, cy)` in 24x24 space.
    let mut raw: Vec<(f32, f32)> = Vec::with_capacity(28);
    // Left bump
    for i in 0..=6 {
        let ang = PI * 0.5 + (i as f32 / 6.0) * PI * 0.88;
        raw.push((-4.4 + ang.cos() * 3.4, 1.4 + ang.sin() * 3.4));
    }
    // Top main dome
    for i in 0..=10 {
        let ang = PI * 1.05 + (i as f32 / 10.0) * PI * 0.92;
        raw.push((-0.3 + ang.cos() * 4.6, -1.0 + ang.sin() * 4.6));
    }
    // Right bump
    for i in 0..=6 {
        let ang = -PI * 0.35 + (i as f32 / 6.0) * PI * 0.85;
        raw.push((4.6 + ang.cos() * 3.2, 1.6 + ang.sin() * 3.2));
    }
    raw.into_iter()
        .map(|(dx, dy)| pt(cx + dx * scale, cy + dy * scale))
        .collect()
}
