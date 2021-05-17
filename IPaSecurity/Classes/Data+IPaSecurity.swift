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

extension Digest
{
    @inlinable public var hexString:String
    {
        get {
            return map { String(format: "%02hhx", $0) }.joined()
        }
        
    }
}
extension HashFunction {
    @inlinable public static func hashString<D>(for data: D) -> String where D : DataProtocol {
        return self.hash(data: data).hexString
    }
}
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
    
    
}

