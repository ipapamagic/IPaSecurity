//
//  NSString+IPaSecurity.swift
//  IPaSecurity
//
//  Created by IPa Chen on 2016/12/28.
//  Copyright © 2016年 AMagicStudio.com. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto

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
        var digest = Digest(algorithm: .md5)
        if let bytes = digest.update(string: self)?.final() {
            return hexString(fromArray: bytes)
        }
        
        return nil
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
    public var md5String:String?
    {
        return (self as String).md5String
    }

}
