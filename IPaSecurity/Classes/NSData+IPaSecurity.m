//
//  NSData+IPaSecurity.m
//  IPaSecurity
//
//  Created by IPaPa on 13/2/7.
//  Copyright (c) 2013 IPaPa. All rights reserved.
//

#import "NSData+IPaSecurity.h"

@implementation NSData (IPaSecurity)
-(NSData*)decryptWithAlgorithm:(CCAlgorithm)algorithm key:(NSData*)key
{
    return [self decryptWithAlgorithm:algorithm mode:kCCModeCBC padding:NO iv:nil key:key];
}
-(NSData*)decryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData*)iv key:(NSData*)key
{
    return [self decryptWithAlgorithm:algorithm mode:mode padding:padding iv:iv key:key options:0];
}
-(NSData*)decryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData*)iv key:(NSData*)key options:(CCModeOptions)options
{
    return [self cipherWithOperation:kCCDecrypt algorighm:algorithm mode:mode padding:padding iv:iv key:key options:options];
}
-(NSData*)encryptWithAlgorithm:(CCAlgorithm)algorithm key:(NSData*)key
{
    return [self encryptWithAlgorithm:algorithm mode:kCCModeCBC padding:NO iv:nil key:key];
}
-(NSData*)encryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData*)iv key:(NSData*)key
{
    return [self encryptWithAlgorithm:algorithm mode:mode padding:padding iv:iv key:key options:0];
}
-(NSData*)encryptWithAlgorithm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData*)iv key:(NSData*)key options:(CCModeOptions)options
{
    return [self cipherWithOperation:kCCEncrypt algorighm:algorithm mode:mode padding:padding iv:iv key:key options:options];
}

-(NSData*)cipherWithOperation:(CCOperation)operation algorighm:(CCAlgorithm)algorithm mode:(CCMode)mode padding:(BOOL)padding iv:(NSData*)iv key:(NSData*)key options:(CCModeOptions)options
{
    //check key size
    switch (algorithm) {
        case kCCAlgorithmAES128:
            if (key.length != kCCKeySizeAES128 && key.length != kCCKeySizeAES192 && key.length != kCCKeySizeAES256) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            
            break;
        case kCCAlgorithmDES:
            if (key.length != kCCKeySizeDES) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            
            break;
        case kCCAlgorithm3DES:
            if (key.length != kCCKeySize3DES) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            
            break;
        case kCCAlgorithmCAST:
            if (key.length < kCCKeySizeMinCAST || key.length > kCCKeySizeMaxCAST) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            
            break;
        case kCCAlgorithmRC4:
            if (key.length < kCCKeySizeMinRC4 || key.length > kCCKeySizeMaxRC4) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            break;
        case kCCAlgorithmRC2:
            if (key.length < kCCKeySizeMinRC2 || key.length > kCCKeySizeMaxRC2) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            
            break;
        case kCCAlgorithmBlowfish:
            if (key.length < kCCKeySizeMinBlowfish || key.length > kCCKeySizeMaxBlowfish) {
                NSLog(@"Encrypt Fail! key size not correct!");
                return nil;
            }
            
            break;
        default:
            break;
    }
    CCCryptorRef cryptorRef;
    //not support XTS mode
    CCCryptorStatus status = CCCryptorCreateWithMode(operation,mode,algorithm,(padding)?ccPKCS7Padding:ccNoPadding, [iv bytes],[key bytes],key.length,NULL,0,0,options,&cryptorRef);
    
    if (status != kCCSuccess) {
        NSLog(@"CCCryptor create fail!");
        return nil;
    }
    
    size_t bufferSize = CCCryptorGetOutputLength(cryptorRef,self.length,true);
    
    
    
    void *buffer = malloc(bufferSize * sizeof(uint8_t));
    size_t movedBytes = 0;
    status = CCCryptorUpdate(cryptorRef,self.bytes,self.length,buffer,bufferSize,&movedBytes);
    if (status != kCCSuccess) {
        NSLog(@"CCCryptor update fail!");
        free(buffer);
        return nil;
    }
    size_t totalBytesWritten = movedBytes;
    void *ptr = buffer + movedBytes;
    size_t remainingBytes = bufferSize - movedBytes;
    
    //no padding and stream cipher ,don't need to call CCCryptorFinal
    status = CCCryptorFinal(cryptorRef, ptr, remainingBytes, &movedBytes);
    if (status != kCCSuccess) {
        NSLog(@"CCCryptor Final fail!....%d",status);
        return nil;
    }
    totalBytesWritten += movedBytes;
    NSData *retData = [NSData dataWithBytesNoCopy:(void *)buffer length:(NSUInteger)totalBytesWritten];
    if (cryptorRef) {
        CCCryptorRelease(cryptorRef);
    }
    
    
    return retData;
}

- (NSData*) SHA256Data
{
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    // This is an iOS5-specific method.
    // It takes in the data, how much data, and then output format, which in this case is an int array.
    CC_SHA256(self.bytes, (CC_LONG)self.length, digest);
    return [[NSData alloc] initWithBytes:digest length:sizeof(uint8_t) * CC_SHA256_DIGEST_LENGTH];
}
-(NSString*) SHA256String
{
    
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    // This is an iOS5-specific method.
    // It takes in the data, how much data, and then output format, which in this case is an int array.
    CC_SHA256(self.bytes, (CC_LONG)self.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    // Parse through the CC_SHA256 results (stored inside of digest[]).
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}
-(NSString*) SHA1String;
{
    
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(self.bytes, (CC_LONG)self.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
    
}
-(NSString*) MD5String
{
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( self.bytes, (CC_LONG)self.length, digest ); // This is the md5 call
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return  output;
    
}
-(NSData*) HMACDataWithAlgorithm:(CCHmacAlgorithm)algorithm secret:(NSData*)key
{
    const void *cKey  = key.bytes;
    const void *cData = self.bytes;
    
    size_t dataSize = 0;
    
    switch (algorithm) {
        case kCCHmacAlgSHA1:
            dataSize = CC_SHA1_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA256:
            dataSize = CC_SHA256_DIGEST_LENGTH;
            break;
        case kCCHmacAlgMD5:
            dataSize = CC_MD5_DIGEST_LENGTH;
            break;
        default:
            break;
    }
    
    if (dataSize > 0) {
        unsigned char *cHMAC;
        cHMAC = malloc(dataSize);
        CCHmac(algorithm, cKey, key.length, cData, self.length, cHMAC);
        NSData *hmacData = [[NSData alloc] initWithBytes:cHMAC length:dataSize];
        
        free(cHMAC);
        return hmacData;
    }
    return nil;
    
}
-(NSString*)HexString
{
    
    char *bytes = (char*)self.bytes;
    
    
    NSMutableString *hexString = [@"" mutableCopy];
    for (NSInteger idx = 0; idx < [self length];idx++)
    {
        [hexString appendFormat:@"%02.2hhx", bytes[idx]];
    }
    
    return hexString;
    
}
//-(NSData*) HMAC_SHA1DataWithSecret:(NSData*)key
//{
//    const void *cKey  = key.bytes;
//    const void *cData = self.bytes;
//
//    unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];
//
//    CCHmac(kCCHmacAlgSHA1, cKey, key.length, cData, self.length, cHMAC);
//
//    return [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
//}
//-(NSData*) HMAC_SHA256DataWithSecret:(NSData*)key
//{
//
//    const void *cKey  = [key bytes];
//    const void *cData = self.bytes;
//
//    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
//
//    CCHmac(kCCHmacAlgSHA256, cKey, [key length], cData, self.length, cHMAC);
//
//    return [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
//
//}
+ (NSData*)dataFromHexString:(NSString*)string
{
    if (string == nil) {
        return nil;
    }
    NSMutableData *data= [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i;
    for (i=0; i < (string.length / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}
-(NSData*)HKDFDataWithAlgorithm:(CCHmacAlgorithm)algorithm Info:(NSData*)info withLength:(NSUInteger)length salt:(NSData*)salt
{
    // Step 1 of RFC 5869
    // Extract
    // Get sha256HMAC Bytes
    // Input: salt (message), IKM (input keyring material)
    // Output: PRK (pseudorandom key)
    NSData *PRK = [self HMACDataWithAlgorithm:algorithm secret:salt];
    
    // Step 2 of RFC 5869.
    // Expand
    // Input: PRK from step 1, info, length.
    // Output: OKM (output keyring material).
    NSInteger iterations = ceil(length);
    NSMutableData *Tn = [NSMutableData data];
    NSMutableData *T = [NSMutableData data];
    for (NSInteger idx = 0;idx < iterations;idx++) {
        [Tn appendData:info];
        const char value = idx+1;
        [Tn appendBytes:&value length:sizeof(const char)];
        Tn = [[Tn HMACDataWithAlgorithm:algorithm secret:PRK] mutableCopy];
        
        [T appendData:Tn];
    }
    return [T subdataWithRange:NSMakeRange(0, length)];
}

@end
