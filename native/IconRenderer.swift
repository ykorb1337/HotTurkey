// Reproducible vector icon renderer, used only while building assets.
import AppKit
import ImageIO
import UniformTypeIdentifiers

func color(_ hex:String)->CGColor {
    let value=UInt32(hex.dropFirst(),radix:16)!
    return CGColor(red:CGFloat((value>>16)&255)/255,green:CGFloat((value>>8)&255)/255,blue:CGFloat(value&255)/255,alpha:1)
}
guard CommandLine.arguments.count==3 else { exit(64) }
let source=try Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1]))
let icon=try JSONSerialization.jsonObject(with:source) as! [String:Any]
let directory=URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true)
try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
for size in [16,19,20,32,38,40,48,64,128,256,512,1024] {
    let space=CGColorSpace(name:CGColorSpace.sRGB)!
    let context=CGContext(data:nil,width:size,height:size,bitsPerComponent:8,bytesPerRow:size*4,space:space,bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.scaleBy(x:CGFloat(size)/1024,y:CGFloat(size)/1024)
    context.translateBy(x:0,y:1024);context.scaleBy(x:1,y:-1)
    let background=icon["background"] as! [String:Any],rect=background["rect"] as! [CGFloat],radius=background["radius"] as! CGFloat
    let tile=CGPath(roundedRect:CGRect(x:rect[0],y:rect[1],width:rect[2],height:rect[3]),cornerWidth:radius,cornerHeight:radius,transform:nil)
    context.saveGState()
    context.setShadow(offset:CGSize(width:0,height:12),blur:24,color:CGColor(gray:0,alpha:0.22))
    context.addPath(tile);context.setFillColor(color("#201A19"));context.fillPath();context.restoreGState()
    context.saveGState();context.addPath(tile);context.clip()
    let colors=(background["colors"] as! [String]).map(color)
    let gradient=CGGradient(colorsSpace:space,colors:colors as CFArray,locations:[0,1])!
    context.drawLinearGradient(gradient,start:CGPoint(x:180,y:100),end:CGPoint(x:800,y:924),options:[]);context.restoreGState()
    for shape in icon["shapes"] as! [[String:Any]] {
        context.setFillColor(color(shape["fill"] as! String))
        if let circle=shape["circle"] as? [CGFloat] {
            context.fillEllipse(in:CGRect(x:circle[0]-circle[2],y:circle[1]-circle[2],width:circle[2]*2,height:circle[2]*2));continue
        }
        let path=CGMutablePath()
        for command in shape["path"] as! [[Any]] {
            let kind=command[0] as! String,values=command.dropFirst().map { ($0 as! NSNumber).doubleValue }
            switch kind {
            case "M":path.move(to:CGPoint(x:values[0],y:values[1]))
            case "L":path.addLine(to:CGPoint(x:values[0],y:values[1]))
            case "C":path.addCurve(to:CGPoint(x:values[4],y:values[5]),control1:CGPoint(x:values[0],y:values[1]),control2:CGPoint(x:values[2],y:values[3]))
            case "Q":path.addQuadCurve(to:CGPoint(x:values[2],y:values[3]),control:CGPoint(x:values[0],y:values[1]))
            default:path.closeSubpath()
            }
        }
        context.addPath(path);context.fillPath()
    }
    let destination=CGImageDestinationCreateWithURL(directory.appendingPathComponent("icon-\(size).png") as CFURL,UTType.png.identifier as CFString,1,nil)!
    CGImageDestinationAddImage(destination,context.makeImage()!,nil)
    guard CGImageDestinationFinalize(destination) else { exit(1) }
}
