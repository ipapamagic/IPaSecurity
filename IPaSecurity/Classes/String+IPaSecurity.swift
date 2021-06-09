//
//  NSString+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/28.
//  Copyright © 2016年 AMagicStudio.com. All rights reserved.
//

import Foundation
import CryptoKit

@available(iOS 13.0, *)
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
    @available(iOS 13.0, *)
    @inlinable public var sha512String:String?
    {
        get {
            return SHA512.hashString(for: self)
        }
    }
    @available(iOS 13.0, *)
    @inlinable public var sha512Data:Data?
    {
        get {
            return SHA512.hash(string: self)
        }
    }
    @inlinable public var sha256String:String?
    {
        get {
            if #available(iOS 13.0, *) {
                return SHA256.hashString(for: self)
            } else {
                // Fallback on earlier versions
                guard let encodeData = data(using: .utf8) else {
                    return nil
                }
                return encodeData.sha256String
            }
        }
    }
    @inlinable public var sha256Data:Data?
    {
        get {
            if #available(iOS 13.0, *) {
                return SHA256.hash(string: self)
            } else {
                // Fallback on earlier versions
                guard let encodeData = data(using: .utf8) else {
                    return nil
                }
                return encodeData.sha256Data
            }
        }
    }
    @inlinable public var sha1String:String?
    {
        get {
            if #available(iOS 13.0, *) {
                return Insecure.SHA1.hashString(for: self)
            } else {
                // Fallback on earlier versions
                guard let encodeData = data(using: .utf8) else {
                    return nil
                }
                return encodeData.sha1String
            }
        }
    
    }
    @inlinable public var md5String:String?
    {
        get {
            if #available(iOS 13.0, *) {
                return Insecure.MD5.hashString(for: self)
            } else {
                // Fallback on earlier versions
                guard let data = self.data(using: .utf8) else {
                    return nil
                }
                return data.md5String
            }
        }

    }
    @inlinable public var snakeCaseString:String? {
        let pattern = "([a-z0-9])([A-Z])"
        
        let regex = try? NSRegularExpression(pattern: pattern, options: [])
        let range = NSRange(location: 0, length: self.count)
        return regex?.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "$1_$2").lowercased()
    }
}


