//
//  NSData+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/27.
//  Copyright © 2016年 IPaPa. All rights reserved.
//

import Foundation
import CommonCrypto
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
    public var hexString:String
    {
        get {
            return map { String(format: "%02hhx", $0) }.joined()
        }
        
    }
    public func cipher(_ operation:CCOperation,algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data,options:CCModeOptions) -> Data?
    {
        
        var _cryptorRef:CCCryptorRef?
        //not support XTS mode
        var ivBytes:UnsafeRawPointer?
        if let _iv = iv {
            ivBytes = (_iv as NSData).bytes
        }
        var status = CCCryptorCreateWithMode(operation,mode,algorithm,CCPadding((padding) ? ccPKCS7Padding : ccNoPadding), ivBytes,(key as NSData).bytes,key.count,nil,0,0,options,&_cryptorRef)
        
        guard let cryptorRef = _cryptorRef,status == noErr else {
            IPaLog("CCCryptor create fail!")
            return nil
        }
        defer {
            _ = CCCryptorRelease(cryptorRef)
        }
        
        
        let bufferSize:size_t = CCCryptorGetOutputLength(cryptorRef,self.count,true)
        
        var result = Data(count:bufferSize)
        var movedBytes: size_t = 0
        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
            return CCCryptorUpdate(
                cryptorRef,
                (self as NSData).bytes, self.count,
                resultBytes, result.count,
                &movedBytes)
        })
        guard status == noErr else {
            IPaLog("CCCryptor update fail!")
            return nil
        }
        
        var totalBytesWritten:size_t = 0
        
        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
            return CCCryptorFinal(
                cryptorRef,
                resultBytes + movedBytes,
                result.count - movedBytes,
                &totalBytesWritten)
        })
        guard status == noErr else {
            IPaLog("CCCryptor Final fail!")
            return nil
        }
        result.count = movedBytes + totalBytesWritten
        return result
    }
    public func decrypt(_ algorithm:CCAlgorithm,key:Data) -> Data?
    {
        return decrypt(algorithm,mode:CCMode(kCCModeCBC),padding:true,iv:nil,key:key)
    }
    public func decrypt(_ algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data) -> Data?
    {
        return decrypt(algorithm,mode:mode,padding:padding,iv:iv,key:key,options:0)
    }
    public func decrypt(_ algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data,options:CCModeOptions) -> Data?
    {
        return cipher(CCOperation(kCCDecrypt),algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:options)
    }
    public func encrypt(_ algorithm:CCAlgorithm, key:Data) -> Data?
    {
        return encrypt(algorithm, mode:CCMode(kCCModeCBC),padding:true ,iv:nil ,key:key)
    }
    public func encrypt(_ algorithm:CCAlgorithm, mode:CCMode ,padding:Bool, iv:Data? ,key:Data) -> Data?
    {
        return encrypt(algorithm,mode:mode,padding:padding,iv:iv,key:key,options:0)
    }
    public func encrypt(_ algorithm:CCAlgorithm, mode:CCMode ,padding:Bool, iv:Data? ,key:Data,options:CCModeOptions) -> Data?
    {
        return cipher(CCOperation(kCCEncrypt),algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:options)
        
    }
    
    public var sha256Data:Data?
    {
        get {
            var digest = Array<UInt8>(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            
            withUnsafeBytes {
                _ = CC_SHA256($0,CC_LONG(self.count),&digest)
            }
            return Data(bytes:digest)
        }
    }
    public var sha256String:String
    {
        get {
            var digest = Array<UInt8>(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            
            withUnsafeBytes {
                _ = CC_SHA256($0,CC_LONG(self.count),&digest)
            }
            var output = ""
            for i in 0 ..< Int(CC_SHA256_DIGEST_LENGTH) {
                
                output += String(format: "%02x", digest[i])
                
            }
            return output;
            
        }
    }
    public var sha1String:String
    {
        get {
            var digest = Array<UInt8>(repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            
            withUnsafeBytes {
                _ = CC_SHA1($0,CC_LONG(self.count),&digest)
            }
            var output = ""
            for i in 0 ..< Int(CC_SHA1_DIGEST_LENGTH) {
                
                output += String(format: "%02x", digest[i])
                
            }
            return output;
        }
    }
    public var md5String:String
    {
        get {
            var digest = Array<UInt8>(repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            
            withUnsafeBytes {
                _ = CC_MD5($0,CC_LONG(self.count),&digest)
            }
            var output = ""
            for i in 0 ..< Int(CC_MD5_DIGEST_LENGTH) {
                
                output += String(format: "%02x", digest[i])
                
            }
            return output;
        }
    }
    
    
}
extension NSData
{
    public static func createData(_ hexString:String) -> Data {
        return Data(hexString:hexString)
    }
    public func encrypt(_ algorithm:CCAlgorithm, key:Data) -> Data?
    {
        return (self as Data).encrypt(algorithm, key: key)
    }
    public func decrypt(_ algorithm:CCAlgorithm,key:Data) -> Data?
    {
        return (self as Data).decrypt(algorithm, key: key)
    }
    public func decrypt(_ algorithm:CCAlgorithm,mode:CCMode,padding:Bool,iv:Data?,key:Data) -> Data?
    {
        return (self as Data).decrypt(algorithm, mode:mode,padding:padding,iv:iv,key:key)
    }
    public func encrypt(_ algorithm:CCAlgorithm, mode:CCMode ,padding:Bool, iv:Data? ,key:Data) -> Data?
    {
        return (self as Data).encrypt(algorithm,mode:mode,padding:padding,iv:iv,key:key)
    }
}
