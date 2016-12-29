//
//  NSData+IPaSecurity.h
//  IPaSecurity
//
//  Created by IPaPa on 13/2/7.
//  Copyright (c) 2013 IPaPa. All rights reserved.
//

#import <Foundation/Foundation.h>
//#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>

@interface NSData (IPaSecurity)
//encryption
//with arguments mode:kCCModeCBC padding:NO iv:nil
-( NSData* _Nullable )encryptWithAlgorithm:(CCAlgorithm)algorithm key:(NSData* _Nullable )key;
-(NSData* _Nullable )encryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData* __nullable)iv key:(NSData* __nonnull)key;
-(NSData* _Nullable)encryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData* __nullable)iv key:(NSData* __nonnull)key options:(CCModeOptions)options;
//decryption
-(NSData* _Nullable)decryptWithAlgorithm:(CCAlgorithm)algorithm key:(NSData* __nonnull)key;
-(NSData* _Nullable)decryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData* __nullable)iv key:(NSData* __nonnull)key;
-(NSData* _Nullable)decryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData* __nullable)iv key:(NSData* __nonnull)key options:(CCModeOptions)options;


-(NSData* _Nullable)cipherWithOperation:(CCOperation)operation algorighm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData* __nullable)iv key:(NSData* __nonnull)key options:(CCModeOptions)options;



-(NSString* __nonnull)SHA1String;
-(NSString* __nonnull)SHA256String;
- (NSData* __nonnull) SHA256Data;
-(NSString* __nonnull)MD5String;
-(NSString* __nonnull)HexString;
+ (NSData* __nonnull)dataFromHexString:(NSString* __nonnull)string;
//currently support kCCHmacAlgSHA1 and kCCHmacAlgSHA256 and kCCHmacAlgMD5 only
-(NSData* _Nullable)HMACDataWithAlgorithm:(CCHmacAlgorithm)algorithm secret:(NSData* __nonnull)key;
-(NSData* _Nullable)HKDFDataWithAlgorithm:(CCHmacAlgorithm)algorithm Info:(NSData* _Nullable)info withLength:(NSUInteger)length salt:(NSData* _Nullable)salt;
@end
