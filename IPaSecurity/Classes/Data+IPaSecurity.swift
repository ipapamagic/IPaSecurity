//
//  NSData+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/27.
//  Copyright © 2016年 IPaPa. All rights reserved.
//

import Foundation
import IPaLog
import CryptoKit
import CommonCrypto
@available(iOS 13.0, *)
extension Digest
{
    @inlinable public var hexString:String
    {
        get {
            return map { String(format: "%02hhx", $0) }.joined()
        }
        
    }
}
@available(iOS 13.0, *)
extension HashFunction {
    @inlinable public static func hashString<D>(for data: D) -> String where D : DataProtocol {
        return self.hash(data: data).hexString
    }
}
@available(iOS 13.0, *)
extension Data
{
    public init(hexString:String) {
        self.init()
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: hexString, options: [], range: NSMakeRange(0, hexString.count)) { match, flags, stop in
            let byteString = (hexString as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            self.append(&num, count: 1)
        }
    }
    @inlinable public var hexString:String
    {
        get {
            return map { String(format: "%02hhx", $0) }.joined()
        }
        
    }
    @inlinable public var sha512Data:Data?
    {
        get {
            let digest = SHA512.hash(data: self)
            return Data(digest)
        }
    }
    @inlinable public var sha256Data:Data?
    {
        get {
            let digest = SHA256.hash(data: self)
            return Data(digest)
        }
    }
    @inlinable public var sha512String:String
    {
        get {
            return SHA512.hashString(for: self)
        }
    }
    @inlinable public var sha256String:String
    {
        get {
            return SHA256.hashString(for: self)
        }
    }
    @inlinable public var sha1String:String
    {
        get {
            return Insecure.SHA1.hashString(for: self)
        }
    }
    @inlinable public var md5String:String
    {
        get {
            return Insecure.MD5.hashString(for: self)
        }
    }
    
    public func aesEncrypt(_ hexKey:String) -> Data? {
        let data = Data(hexString: hexKey)
        let symmetricKey = SymmetricKey(data: data)
        guard let sealedData = try? AES.GCM.seal(self, using: symmetricKey) else {
            return nil
        }
        return sealedData.combined
    }
    public func aesDecrypt(_ hexKey:String) -> Data? {
        
        guard let sealedBox = try? AES.GCM.SealedBox(combined: self) else {
            return nil
        }
        let data = Data(hexString: hexKey)
        let symmetricKey = SymmetricKey(data: data)
        return try? AES.GCM.open(sealedBox, using: symmetricKey)
    }
    public func desEncrypt(_ hexKey:String) -> Data? {
        return self.cipher(CCOperation(kCCEncrypt), algorithm: CCAlgorithm(kCCAlgorithmDES), key: Data(hexString: hexKey))
    }
    public func desDecrypt(_ hexKey:String) -> Data? {
        return self.cipher(CCOperation(kCCDecrypt), algorithm: CCAlgorithm(kCCAlgorithmDES), key: Data(hexString: hexKey))
    }
    
}
// CryptoCommon
extension Data
{
    
    func cipher(_ operation:CCOperation,algorithm:CCAlgorithm,mode:CCMode = CCMode(kCCModeCBC),padding:Bool = true,iv:Data? = nil,key:Data,options:CCModeOptions = 0) -> Data?
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
        let resultCount = result.count
        var movedBytes: size_t = 0
        
        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutableRawBufferPointer) -> CCCryptorStatus in
            return CCCryptorUpdate(
                cryptorRef,
                (self as NSData).bytes, self.count,
                resultBytes.baseAddress, resultCount,
                &movedBytes)
        })
        guard status == noErr else {
            IPaLog("CCCryptor update fail!")
            return nil
        }
        
        var totalBytesWritten:size_t = 0
        
        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutableRawBufferPointer) -> CCCryptorStatus in
            return CCCryptorFinal(
                cryptorRef,
                resultBytes.baseAddress! + movedBytes,
                resultCount - movedBytes,
                &totalBytesWritten)
        })
        guard status == noErr else {
            IPaLog("CCCryptor Final fail!")
            return nil
        }
        result.count = movedBytes + totalBytesWritten
        return result
    }
    
    func decrypt(_ algorithm:CCAlgorithm,mode:CCMode = CCMode(kCCModeCBC) ,padding:Bool = true,iv:Data? = nil,key:Data,options:CCModeOptions = 0) -> Data?
    {
        return cipher(CCOperation(kCCDecrypt),algorithm:algorithm,mode:mode,padding:padding,iv:iv,key:key,options:options)
    }
}
