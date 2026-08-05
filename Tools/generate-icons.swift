//
//  generate-icons.swift
//  Dev-only tool (not shipped) — renders Mabure's app icon (a squircle badge
//  with an original chrome alien-head mark — a nod to "detecting the
//  foreign process" — drawn from scratch with bezier paths, not traced from
//  any existing logo/asset) and the menu-bar glyph variants.
//
//  Usage: swift Tools/generate-icons.swift
//  Output: build/icon-preview.png (quick look), build/AppIcon.iconset/*,
//           Resources/AppIcon.icns, Resources/MenuBarIcons/*.png
//

import AppKit

let fm = FileManager.default
let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let buildDir = repoRoot.appendingPathComponent("build")
let iconsetDir = buildDir.appendingPathComponent("AppIcon.iconset")
let resourcesDir = repoRoot.appendingPathComponent("Resources")
let menuBarDir = resourcesDir.appendingPathComponent("MenuBarIcons")

try? fm.createDirectory(at: iconsetDir, withIntermediateDirectories: true)
try? fm.createDirectory(at: menuBarDir, withIntermediateDirectories: true)

// MARK: - Squircle path (Big Sur-style rounded-square mask)

func squirclePath(in rect: NSRect, cornerRatio: CGFloat = 0.223) -> NSBezierPath {
    let radius = min(rect.width, rect.height) * cornerRatio
    return NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
}

// MARK: - Alien head geometry (original — hand-built bezier curves, not
// traced from any source image). Defined in a normalized local space:
// x in [-0.5, 0.5], y in [0, 1] where 0 = chin tip, 1 = crown apex. Widest
// point of the head sits at y≈0.62.

func headPath(in rect: NSRect) -> NSBezierPath {
    let w = rect.width
    let h = rect.height
    func pt(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
        NSPoint(x: rect.midX + x * w, y: rect.minY + y * h)
    }

    let path = NSBezierPath()
    path.move(to: pt(0, 1.0))                                        // crown apex
    path.curve(to: pt(0.42, 0.64),                                   // right widest point
               controlPoint1: pt(0.20, 1.02), controlPoint2: pt(0.42, 0.90))
    path.curve(to: pt(0, 0.0),                                       // chin tip
               controlPoint1: pt(0.36, 0.32), controlPoint2: pt(0.14, 0.05))
    path.curve(to: pt(-0.42, 0.64),                                  // left widest point
               controlPoint1: pt(-0.14, 0.05), controlPoint2: pt(-0.36, 0.32))
    path.curve(to: pt(0, 1.0),                                       // back to crown
               controlPoint1: pt(-0.42, 0.90), controlPoint2: pt(-0.20, 1.02))
    path.close()
    return path
}

/// One almond eye, pointed at the inner-bottom (near the nose bridge) and
/// swept up-and-out to a rounder outer-top corner — mirrored for the left
/// eye by flipping x.
func eyePath(in rect: NSRect, mirrored: Bool) -> NSBezierPath {
    let w = rect.width
    let h = rect.height
    func pt(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
        let sx = mirrored ? -x : x
        return NSPoint(x: rect.midX + sx * w, y: rect.minY + y * h)
    }

    let inner = pt(0.0, 0.46)      // near the nose bridge, sits low
    let outer = pt(0.42, 0.78)     // swept up and outward toward the temple

    let path = NSBezierPath()
    path.move(to: inner)
    // top edge and bottom edge control points are offset perpendicular to
    // the inner->outer line (not just "above/below" in y) so the almond
    // actually fattens instead of just lengthening as a thin slit.
    path.curve(to: outer, controlPoint1: pt(0.1106, 0.6197), controlPoint2: pt(0.2185, 0.7396))
    path.curve(to: inner, controlPoint1: pt(0.3275, 0.5964), controlPoint2: pt(0.1834, 0.5243))
    path.close()
    return path
}

// MARK: - App icon: dark badge + chrome alien head with cut-out eyes

func renderAppIcon(size: CGFloat) -> NSImage {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    defer { image.unlockFocus() }

    let rect = NSRect(x: 0, y: 0, width: size, height: size)
    let badgePath = squirclePath(in: rect)
    badgePath.addClip()

    let bgColor = NSColor(calibratedRed: 0.075, green: 0.078, blue: 0.098, alpha: 1.0)  // near-black charcoal
    bgColor.setFill()
    rect.fill()

    // Head bounding box: centered, with a little breathing room from the badge edges.
    let headRect = NSRect(
        x: size * 0.19, y: size * 0.11,
        width: size * 0.62, height: size * 0.80
    )

    NSGraphicsContext.saveGraphicsState()
    let head = headPath(in: headRect)
    head.addClip()

    // Chrome gradient: light steel highlight upper-left, sinking to a
    // darker gunmetal at the lower-right — the classic "brushed chrome
    // sphere" shading trick, done with a single diagonal linear gradient.
    let chrome = NSGradient(colors: [
        NSColor(calibratedWhite: 0.97, alpha: 1.0),
        NSColor(calibratedWhite: 0.80, alpha: 1.0),
        NSColor(calibratedWhite: 0.55, alpha: 1.0),
        NSColor(calibratedWhite: 0.38, alpha: 1.0),
    ], atLocations: [0.0, 0.35, 0.72, 1.0], colorSpace: .deviceGray)
    chrome?.draw(in: headRect, angle: -55)

    // A soft, elongated specular highlight along the upper-left of the dome.
    let specular = NSBezierPath(ovalIn: NSRect(
        x: headRect.minX + headRect.width * 0.06, y: headRect.minY + headRect.height * 0.60,
        width: headRect.width * 0.42, height: headRect.height * 0.34
    ))
    let specularGradient = NSGradient(colors: [
        NSColor.white.withAlphaComponent(0.55),
        NSColor.white.withAlphaComponent(0.0),
    ])
    specularGradient?.draw(in: specular, angle: -55)

    NSGraphicsContext.restoreGraphicsState()

    // A fine rim light around the head silhouette for edge definition
    // against the dark badge.
    head.lineWidth = max(1, size * 0.006)
    NSColor(calibratedWhite: 1.0, alpha: 0.35).setStroke()
    head.stroke()

    // Eyes: cut back down to the badge background color so they read as
    // deep, dark sockets — same trick the reference aesthetic uses.
    bgColor.setFill()
    eyePath(in: headRect, mirrored: false).fill()
    eyePath(in: headRect, mirrored: true).fill()

    return image
}

// MARK: - Menu bar glyph: head silhouette with cut-out eyes, single color

func renderMenuBarGlyph(size: CGFloat, color: NSColor) -> NSImage {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    defer { image.unlockFocus() }
    let rect = NSRect(x: 0, y: 0, width: size, height: size)
    let headRect = rect.insetBy(dx: size * 0.14, dy: size * 0.03)

    let head = headPath(in: headRect)
    color.setFill()
    head.fill()

    // Punch the eyes out as true transparency (not just a matching fill),
    // so this still reads correctly once AppKit re-tints a template image.
    NSGraphicsContext.current?.compositingOperation = .destinationOut
    NSColor.black.setFill()
    eyePath(in: headRect, mirrored: false).fill()
    eyePath(in: headRect, mirrored: true).fill()
    NSGraphicsContext.current?.compositingOperation = .sourceOver

    return image
}

func pngData(_ image: NSImage, size: CGFloat) -> Data? {
    guard let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) else { return nil }
    rep.size = NSSize(width: size, height: size)
    return rep.representation(using: .png, properties: [:])
}

// MARK: - App icon: full iconset

let iconSizes: [(name: String, points: CGFloat, scale: Int)] = [
    ("icon_16x16", 16, 1), ("icon_16x16@2x", 16, 2),
    ("icon_32x32", 32, 1), ("icon_32x32@2x", 32, 2),
    ("icon_128x128", 128, 1), ("icon_128x128@2x", 128, 2),
    ("icon_256x256", 256, 1), ("icon_256x256@2x", 256, 2),
    ("icon_512x512", 512, 1), ("icon_512x512@2x", 512, 2),
]

for entry in iconSizes {
    let px = entry.points * CGFloat(entry.scale)
    let image = renderAppIcon(size: px)
    if let data = pngData(image, size: px) {
        try? data.write(to: iconsetDir.appendingPathComponent("\(entry.name).png"))
    }
}

if let data = pngData(renderAppIcon(size: 512), size: 512) {
    try? data.write(to: buildDir.appendingPathComponent("icon-preview.png"))
}

// MARK: - Menu bar glyphs — watching (template), paused (gray), unreachable (amber)

// One high-res master PNG per state — no "@2x" filename pairing. AppKit's
// automatic @1x/@2x resolution via NSImage(named:) turned out fragile here
// (see StatusItemController's loader comment): the "@2x" file's *declared*
// logical size must equal the @1x file's, not double it, and lockFocus'
// own backing-scale rendering made that easy to get wrong. Simpler and
// robust: render once at a comfortably high resolution, load the raw file
// in code, and pin the target point size explicitly there.
let menuBarVariants: [(name: String, color: NSColor, template: Bool)] = [
    ("icon-watching", .black, true),
    ("icon-paused", NSColor(calibratedWhite: 0.55, alpha: 1.0), false),
    ("icon-unreachable", NSColor(calibratedRed: 0.93, green: 0.29, blue: 0.20, alpha: 1.0), false),
]

let menuBarMasterPixels: CGFloat = 128  // plenty of headroom above any Retina menu bar target

for variant in menuBarVariants {
    let image = renderMenuBarGlyph(size: menuBarMasterPixels, color: variant.color)
    if let data = pngData(image, size: menuBarMasterPixels) {
        try? data.write(to: menuBarDir.appendingPathComponent("\(variant.name).png"))
    }
}

print("Wrote iconset to \(iconsetDir.path)")
print("Wrote preview to \(buildDir.appendingPathComponent("icon-preview.png").path)")
print("Wrote menu bar glyphs to \(menuBarDir.path)")
