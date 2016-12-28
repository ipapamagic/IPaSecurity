//
//  NSData+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/27.
//  Copyright © 2016年 IPaPa. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto
import IPaLog
extension Data
{
    init(hexString:String) {
        self.init()
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: hexString, options: [], range: NSMakeRange(0, hexString.characters.count)) { match, flags, stop in
            let byteString = (hexString as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            self.append(&num, count: 1)
        }
    }
//    public func cipher(operation:CCOperation,algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data,options:CCModeOptions) -> Data?
//    {
//        
//        var _cryptorRef:CCCryptorRef?
//        //not support XTS mode
//        var ivBytes:UnsafeRawPointer?
//        if let _iv = iv {
//            ivBytes = (_iv as NSData).bytes
//        }
//        var status = CCCryptorCreateWithMode(operation,mode,algorithm,CCPadding((padding) ? ccPKCS7Padding : ccNoPadding), ivBytes,(key as NSData).bytes,key.count,nil,0,0,options,&_cryptorRef)
//        
//        guard let cryptorRef = _cryptorRef,status == noErr else {
//            IPaLog("CCCryptor create fail!")
//            return nil
//        }
//        defer {
//            _ = CCCryptorRelease(cryptorRef)
//        }
//        
//        
//        let bufferSize:size_t = CCCryptorGetOutputLength(cryptorRef,self.count,true)
//        
//        var result = Data(count:bufferSize)
//        var movedBytes: size_t = 0
//        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
//            return CCCryptorUpdate(
//                cryptorRef,
//                (self as NSData).bytes, self.count,
//                resultBytes, result.count,
//                &movedBytes)
//        })
//        guard status == noErr else {
//            IPaLog("CCCryptor update fail!")
//            return nil
//        }
//        
//        var totalBytesWritten:size_t = 0
//        
//        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
//            return CCCryptorFinal(
//                cryptorRef,
//                resultBytes + movedBytes,
//                result.count - movedBytes,
//                &totalBytesWritten)
//        })
//        guard status == noErr else {
//            IPaLog("CCCryptor Final fail!")
//            return nil
//        }
//        result.count = movedBytes + totalBytesWritten
//        return result
//    }
//    public func decrypt(algorithm:CCAlgorithm,key:Data) -> Data?
//    {
//        return decrypt(algorithm:algorithm,mode:CCMode(kCCModeCBC),padding:false,iv:nil,key:key)
//    }
//    public func decrypt(algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data) -> Data?
//    {
//        return decrypt(algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:0)
//    }
//    public func decrypt(algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data,options:CCModeOptions) -> Data?
//    {
//        return cipher(operation:CCOperation(kCCDecrypt),algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:options)
//    }
//    public func encrypt(algorithm:CCAlgorithm, key:Data) -> Data?
//    {
//        return encrypt(algorithm:algorithm, mode:CCMode(kCCModeCBC),padding:false ,iv:nil ,key:key)
//    }
//    public func encrypt(algorithm:CCAlgorithm, mode:CCMode ,padding:Bool, iv:Data? ,key:Data) -> Data?
//    {
//        return encrypt(algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:0)
//    }
//    public func encrypt(algorithm:CCAlgorithm, mode:CCMode ,padding:Bool, iv:Data? ,key:Data,options:CCModeOptions) -> Data?
//    {
//        return cipher(operation:CCOperation(kCCEncrypt),algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:options)
//        
//    }
    
    public var sha256Data:Data?
        {
        get {
            var sha256Digest = Digest(algorithm: .sha256)
            if let bytes = sha256Digest.update(data: self)?.final() {
                return Data(bytes: bytes)
            }
            return nil
        }
    }
    public var sha256String:String?
        {
        get {
            var digest = Digest(algorithm: .sha256)
            if let bytes = digest.update(data: self)?.final() {
                
                // Parse through the CC_SHA256 results (stored inside of digest[]).
                return hexString(fromArray: bytes)
            }
            return nil
        }
    }
    public var sha1String:String?
        {
        get {
            var digest = Digest(algorithm: .sha1)
            if let bytes = digest.update(data: self)?.final() {
                return hexString(fromArray: bytes)
            }
            return nil
        }
    }
    public var md5String:String?
        {
        get {
            var digest = Digest(algorithm: .md5)
            if let bytes = digest.update(data: self)?.final() {
                return hexString(fromArray: bytes)
            }
            
            return nil
        }
    }
    
    public var hex:String
    {
        get {
            return map { String(format: "%02hhx", $0) }.joined()
        }
        
    }
}
