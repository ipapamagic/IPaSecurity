//
//  NSString+IPaSecurity.h
//  IPaSecurity
//
//  Created by IPaPa on 13/2/7.
//  Copyright (c) 2013 IPaPa. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (IPaSecurity)
-(NSString*) SHA1String;
-(NSString*) SHA256String;
- (NSData*) SHA256Data;
-(NSString*) MD5String;
//-(NSString*)stringWithURLEncode;
@end
