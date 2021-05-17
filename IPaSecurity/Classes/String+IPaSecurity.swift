//
//  NSString+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/28.
//  Copyright © 2016年 AMagicStudio.com. All rights reserved.
//

import Foundation
import CryptoKit

extension HashFunction {

    @inlinable public static func hashString(for string: String) -> String? {
        guard let encodeData = string.data(using: .utf8) else {
            return nil
        }
        return self.hash(data: encodeData).hexString
    }
    @inlinable public static func hash(string: String) -> Data?  {
        guard let encodeData = string.data(using: .utf8) else {
            return nil
        }
        return Data(self.hash(data: encodeData))
    }
}
extension String {
    @inlinable public var sha512String:String?
    {
        get {
            return SHA512.hashString(for: self)
        }
    }
    @inlinable public var sha512Data:Data?
    {
        get {
            return SHA512.hash(string: self)
        }
    }
    @inlinable public var sha256String:String?
    {
        get {
            return SHA256.hashString(for: self)
        }
    }
    @inlinable public var sha256Data:Data?
    {
        get {
            return SHA256.hash(string: self)
        }
    }
    @inlinable public var sha1String:String?
    {
        get {
            return Insecure.SHA1.hashString(for: self)
        }
    
    }
    @inlinable public var md5String:String?
    {
        get {
            return Insecure.MD5.hashString(for: self)
        }

    }
    @inlinable public var snakeCaseString:String? {
        let pattern = "([a-z0-9])([A-Z])"
        
        let regex = try? NSRegularExpression(pattern: pattern, options: [])
        let range = NSRange(location: 0, length: self.count)
        return regex?.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "$1_$2").lowercased()
    }
}


extension NSString {
    public var sha256String:String?
        {
        get {
            return (self as String).sha256String
        }
    }
    public var sha256Data:Data?
        {
        get {
            return (self as String).sha256Data
        }
    }
    public var sha1String:String?
        {
        get {
            return (self as String).sha1String
        }
        
    }
    @objc public var md5String:String?
    {
        return (self as String).md5String
    }
    
}
