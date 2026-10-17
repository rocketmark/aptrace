import Foundation
import PDFKit
import AppKit
let args = CommandLine.arguments
let input = args[1]
let output = args[2]
guard let doc = PDFDocument(url: URL(fileURLWithPath: input)) else { fatalError("Cannot open PDF") }
print("pages=\(doc.pageCount)")
print(doc.documentAttributes ?? [:])
if args.count == 3 {
 var text = ""
 for i in 0..<doc.pageCount { text += "\n===== PDF PAGE \(i+1) =====\n" + (doc.page(at:i)?.string ?? "") + "\n" }
 try text.write(toFile: output, atomically:true, encoding:.utf8)
} else {
 let n = Int(args[3])! - 1
 let page = doc.page(at:n)!
 let rect = page.bounds(for:.mediaBox)
 let scale:CGFloat = 1.7
 let img = NSImage(size:NSSize(width:rect.width*scale,height:rect.height*scale))
 img.lockFocus()
 NSColor.white.setFill(); NSBezierPath(rect:NSRect(origin:.zero,size:img.size)).fill()
 let ctx = NSGraphicsContext.current!.cgContext
 ctx.scaleBy(x:scale,y:scale)
 page.draw(with:.mediaBox,to:ctx)
 img.unlockFocus()
 let rep = NSBitmapImageRep(data:img.tiffRepresentation!)!
 try rep.representation(using:.png,properties:[:])!.write(to:URL(fileURLWithPath:output))
}
