//
//  NSString+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/28.
//  Copyright © 2016年 AMagicStudio.com. All rights reserved.
//

import Foundation
import CommonCrypto

extension String {
    public var sha256String:String?
    {
        get {
            guard let encodeData = data(using: .utf8) else {
                return nil
            }
            return encodeData.sha256String
        }
    }
    public var sha256Data:Data?
    {
        get {
            guard let encodeData = data(using: .utf8) else {
                return nil
            }
            return encodeData.sha256Data
        }
    }
    public var sha1String:String?
    {
        get {
            guard let encodeData = data(using: .utf8) else {
                return nil
            }
            return encodeData.sha1String
        }
    
    }
    public var md5String:String?
    {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        return data.md5String

    }
    public var snakeCaseString:String? {
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
