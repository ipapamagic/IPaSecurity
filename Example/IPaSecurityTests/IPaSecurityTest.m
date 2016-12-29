//
//  IPaSecurityTest.m
//  IPaSecurityTest
//
//  Created by IPaPa on 13/2/7.
//  Copyright (c) 2013年 IPaPa. All rights reserved.
//

#import "IPaSecurityTest.h"
#import <IPaSecurity/NSData+IPaSecurity.h>
#import <IPaSecurity/NSString+IPaSecurity.h>
@implementation IPaSecurityTest

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}


- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}



#pragma mark - Test Case
-(void)testSHA256
{
    NSDictionary *testCase = @{ @"ROCK":@"5adfabaf0034944241e990102d633da1570763930acbb84213b8552bd393a17c",
        @"RACK":@"24f13e344a25bc712673222c17042a71d5860f0ad0b2acb23cac226880993608",
        @"ROCKY":@"8fb0c6406e29577e4908d5ba5bc35ec98b08cec26debf76c3d6ecf88774bf264",
        @"Rock'S saying":@"48c7c57ca89c80fe1f0e0759c833b7b8c9cde6ac8fe42675c9299534c083e772"};
    for (NSString *key in testCase) {
        NSString *result = [key SHA256String];
        NSString *realResult = testCase[key];
        if (![result isEqualToString:realResult]) {
            
            XCTFail(@"SHA1 fail!! result should be %@ but  %@  instead!",result,realResult);
        }
    }
}
- (void)testSHA1
{
    NSDictionary *testCase = @{ @"ROCK":@"8f97f5a81bc2a63f2e65b956b0cd5ac334284509",
                                @"RACK":@"ac61253a34bf8d851a1e251d0fa4856527feaa88",
                                @"ROCKY":@"99457410e3c1857f33279f23781ed6ebc93deb4c",
                                @"Rock'S saying":@"a60cee862827c2fc45cb4a7f285f6bfba1a643e8",
                                [NSData dataFromHexString:@"a0b1c2d3e4f5"]:@"09162b88bcd444138251012ac80e1444a820259a" };
    for (NSString *key in testCase) {
        NSString *result = [key SHA1String];
        NSString *realResult = testCase[key];
        if (![result isEqualToString:realResult]) {
            
            XCTFail(@"SHA1 fail!! result should be %@ but  %@  instead!",result,realResult);
        }
    }
}
-(void)testMD5
{
    NSDictionary *testCase = @{ @"ROCK":@"afeb717aa2a101f7f64840e0be38c171",
                                @"RACK":@"1ece4bad0efe8b897c6e7f8bd101759f",
                                @"ROCKY":@"6cd910740cbbbbd0f55238a93fba157d",
                                @"Rock'S saying":@"7dca0df0dfa7f76b652e53daa4852640"};
    for (NSString *key in testCase) {
        NSString *result = [key MD5String];
        NSString *realResult = testCase[key];
        if (![result isEqualToString:realResult]) {
            
            XCTFail(@"MD5 fail!! result should be %@ but  %@  instead!",result,realResult);
        }
    }
   
}


-(void)testHKDF
{
    
    NSArray *sha256testData = @[@{@"IKM": @"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                            @"salt":@"000102030405060708090a0b0c",
                            @"info":@"f0f1f2f3f4f5f6f7f8f9",
                            @"realPRK":@"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                            @"realOKM":@"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                            @"length":@42},
                          @{@"IKM": @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                            @"salt":@"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                            @"info":@"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                            @"realPRK":@"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                            @"realOKM":@"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
                            @"length":@82},
                          @{@"IKM": @"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                            
                            @"realPRK":@"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                            @"realOKM":@"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                            @"length":@42},
                                @{@"IKM":@"a0a1a2a3a4a5a6a7b0b1b2b3b4b5b6b7c0c1c2c3c4c5c6c7d0d1d2d3d4d5d6d7",
                                    @"info":@"09162b88bcd444138251012ac80e1444a820259a",
                                  @"realOKM":@"95273b071820f54ed10df47458997e5188821e0073579cdfc097426cdbc947d5",@"length":@32}];
    

    for (NSDictionary *data in sha256testData) {
        NSData *IKM = [NSData dataFromHexString:data[@"IKM"]];
        NSData *salt = [NSData dataFromHexString:data[@"salt"]];
        NSData *info = [NSData dataFromHexString:data[@"info"]];

        NSData* realPRK = [NSData dataFromHexString:data[@"realPRK"]];
        if (realPRK != nil) {
            NSData *PRK = [IKM HMACDataWithAlgorithm:kCCHmacAlgSHA256 secret:salt];
            if (![PRK isEqualToData:realPRK])
            {
                NSLog(@"PRK:%@",PRK);
                NSLog(@"correct PRK:%@",realPRK);
                
                XCTFail(@"HKDF SHA256 fail!! PRK not correct!");
            }

        }
        
        
        NSData *OKM = [IKM HKDFDataWithAlgorithm:kCCHmacAlgSHA256 Info:info withLength:[data[@"length"] integerValue] salt:salt];
        NSData *realOKM = [NSData dataFromHexString:data[@"realOKM"]];
        if (![OKM isEqualToData:realOKM])
        {
            NSLog(@"OKM:%@",OKM);
            NSLog(@"correct OKM:%@",realOKM);
            
            XCTFail(@"HKDF SHA256 fail!! OKM not correct!");
        }

    }
 
    
    
    
    NSArray *sha1testData = @[@{@"IKM": @"0b0b0b0b0b0b0b0b0b0b0b",
                                  @"salt":@"000102030405060708090a0b0c",
                                  @"info":@"f0f1f2f3f4f5f6f7f8f9",
                                  @"realPRK":@"9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                                  @"realOKM":@"085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
                                  @"length":@42},
                              @{@"IKM": @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                                @"salt":@"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                                @"info":@"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                                  	@"realPRK":@"8adae09a2a307059478d309b26c4115a224cfaf6",
                                @"realOKM":@"0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
                                  @"length":@82},
                                @{@"IKM": @"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                                  
                                  @"realPRK":@"da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
                                  @"realOKM":@"0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
                                  @"length":@42},
                              @{@"IKM": @"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                                
                                @"realPRK":@"2adccada18779e7c2077ad2eb19d3f3e731385dd",
                                @"realOKM":@"2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
                                @"length":@42}];
    
    
    for (NSDictionary *data in sha1testData) {
        NSData *IKM = [NSData dataFromHexString:data[@"IKM"]];
        NSData *salt = [NSData dataFromHexString:data[@"salt"]];
        NSData *info = [NSData dataFromHexString:data[@"info"]];
        NSData *PRK = [IKM HMACDataWithAlgorithm:kCCHmacAlgSHA1 secret:salt];
        NSData* realPRK = [NSData dataFromHexString:data[@"realPRK"]];
        if (realPRK != nil) {
            if (![PRK isEqualToData:realPRK])
            {
                NSLog(@"PRK:%@",PRK);
                NSLog(@"correct PRK:%@",realPRK);
                
                XCTFail(@"HKDF SHA1 fail!! PRK not correct!");
            }
        }
        
        NSData *OKM = [IKM HKDFDataWithAlgorithm:kCCHmacAlgSHA1 Info:info withLength:[data[@"length"] integerValue] salt:salt];
        NSData *realOKM = [NSData dataFromHexString:data[@"realOKM"]];
        if (![OKM isEqualToData:realOKM])
        {
            NSLog(@"OKM:%@",OKM);
            NSLog(@"correct OKM:%@",realOKM);
            
            XCTFail(@"HKDF SHA1 fail!! OKM not correct!");
        }
        
    }
    


}

-(void)testAES
{
    NSDictionary *testCaseList = @{@(kCCModeCBC):@[@{@"Key": @"06a9214036b8a15b512e03d534120006",
                                @"PlainText":@"53696e676c6520626c6f636b206d7367",
                                @"realCipherData":@"e353779c1079aeb82708942dbe77181a",
                                @"iv":@"3dafba429d9eb430b422da802c9fac41"},
                              @{@"Key": @"c286696d887c9aa0611bbb3e2025a45a",
                                @"PlainText":@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                                @"realCipherData":@"d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1",
                                @"iv":@"562e17996d093d28ddb3ba695a2e6f58"},
                              @{@"Key": @"6c3ea0477630ce21a2ce334aa746c2cd",
                                @"PlainText":@"5468697320697320612034382d62797465206d657373616765202865786163746c7920332041455320626c6f636b7329",
                                @"realCipherData":@"d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684",
                                @"iv":@"c782dc4c098c66cbd9cd27d825682c81"},
                              @{@"Key": @"56e47a38c5598974bc46903dba290349",
                                @"PlainText":@"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",@"realCipherData":@"c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55",
                                @"iv":@"8ce82eefbea0da3c44699ed7db51b7d9"}],
                                   @(kCCModeOFB):@[@{@"Key": @"95273b071820f54ed10df47458997e5188821e0073579cdfc097426cdbc947d5",
                                                   @"PlainText":@"303931363262383862636434343431333832353130313261633830653134343461383230323539617c312e317c6c6f67696e7c323031332d30312d30315431323a33343a35365a7c2d2de6b8ace8a9a6e8b387e696992d2d6221bcbc273da52c746c0ce91025990626ef3338",@"realCipherData":@"1026753f3cf36eccddf4b75736e42fc958a12f5eac3f38d380842dcf1b5bae7fcdd2752db4b1cdf15f0e8d658bacca1b64ab142dd65e8057f201417021c4743382ea4ec088968e5771f5c1347ce74fd924166168d0e397e70bb58cd158ff58dad274792ed4b2c3151522ff4e"}]};
    
       
    
    for (NSNumber* testMode in testCaseList) {
        NSArray *testList  = testCaseList[testMode];
        CCMode mode = [testMode integerValue];
        for (NSDictionary* testCase in testList) {
            
            
            NSData *plainText = [NSData dataFromHexString:testCase[@"PlainText"]];
            NSData *key = [NSData dataFromHexString:testCase[@"Key"]];
            NSData *realCipherData = [NSData dataFromHexString:testCase[@"realCipherData"]];
            NSData *iv = [NSData dataFromHexString:testCase[@"iv"]];
            NSData *cipherData = [plainText encryptWithAlgorithm:kCCAlgorithmAES128 mode:mode padding:NO iv:iv key:key];
            
            NSString *modeName;
            switch (mode) {
                case kCCModeCBC:
                    modeName = @"kCCModeCBC";
                    break;
                case kCCModeOFB:
                    modeName = @"kCCModeOFB";
                    break;
                default:
                    break;
            }
            
            
            if (![cipherData isEqualToData:realCipherData]) {
                NSLog(@"Mode Name:%@",modeName);
                NSLog(@"cipher data:%@",cipherData);
                NSLog(@"correct cipher data:%@",realCipherData);
                
                XCTFail(@"AES fail!! encrypt not correct");
            }
            NSData *decryptData = [cipherData decryptWithAlgorithm:kCCAlgorithmAES128 mode:mode padding:NO iv:iv key:key];
            if (![decryptData isEqualToData:plainText]) {
                NSLog(@"Mode Name:%@",modeName);                
                NSLog(@"decrypt data:%@",decryptData);
                NSLog(@"correct decrypt data:%@",plainText);
                
                XCTFail(@"AES fail!! decrypt not correct");
            }
        }
    }
    
    
}
-(void)testDES2
{
    NSDictionary *testData = @{
                           @"email":@"aaaaaaaaaa@gmail.com",
                           @"id":@"12310202199454702557",
                           @"name":@"abcabcabcabcabc",
                           @"phone":@"12345678901",
                           };
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:testData];
    NSData *encryptData = [data encryptWithAlgorithm:kCCAlgorithmDES mode:kCCModeECB padding:YES iv:nil key:[NSData dataFromHexString:@"38627974656B6579"]];
    
    
    
    data = [encryptData decryptWithAlgorithm:kCCAlgorithmDES mode:kCCModeECB padding:YES iv:nil key:[NSData dataFromHexString:@"38627974656B6579"]];
    
    
    NSDictionary *resultData = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    if (![testData isEqual:resultData]) {
        XCTFail(@"DES fail!! decrypt not correct");
    }
}
-(void)testDES
{
    NSArray *testCaseList = @[@{@"Key": @"133457799BBCDFF1",
                                @"PlainText":@"0123456789ABCDEF",
                                @"realCipherData":@"85E813540F0AB405"},
                              @{@"Key": @"38627974656B6579",
                                @"PlainText":@"6D6573736167652E",
                                @"realCipherData":@"7CF45E129445D451"},
                             ];
    
    
    
    for (NSDictionary* testCase in testCaseList) {
        NSData *plainText = [NSData dataFromHexString:testCase[@"PlainText"]];
        NSData *key = [NSData dataFromHexString:testCase[@"Key"]];
        NSData *realCipherData = [NSData dataFromHexString:testCase[@"realCipherData"]];
        NSData *cipherData = [plainText encryptWithAlgorithm:kCCAlgorithmDES key:key];
        
        if (![cipherData isEqualToData:realCipherData]) {
            NSLog(@"cipher data:%@",cipherData);
            NSLog(@"correct cipher data:%@",realCipherData);
            
            XCTFail(@"DES fail!! encrypt not correct");
        }
        NSData *decryptData = [cipherData decryptWithAlgorithm:kCCAlgorithmDES key:key];
        if (![decryptData isEqualToData:plainText]) {
            NSLog(@"decrypt data:%@",decryptData);
            NSLog(@"correct decrypt data:%@",plainText);
            
            XCTFail(@"DES fail!! decrypt not correct");
        }
    }
    
    
}

-(void)testHmac
{
    NSDictionary *testData = @{@(kCCHmacAlgMD5):@[
                          @{@"key": [NSData dataFromHexString:@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"],@"data":[@"Hi There" dataUsingEncoding:NSUTF8StringEncoding],@"correctHmac":@"9294727a3638bb1c13f48ef8158bfc9d"},
                          @{@"key": [@"Jefe" dataUsingEncoding:NSUTF8StringEncoding],@"data":[@"what do ya want for nothing?" dataUsingEncoding:NSUTF8StringEncoding],@"correctHmac":@"750c783e6ab0b503eaa86e310a5db738"},
                          @{@"key": [NSData dataFromHexString:@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],@"data":[NSData dataFromHexString:@"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"],@"correctHmac":@"56be34521d144c88dbb8c733f0e8b3f6"}],
                        @(kCCHmacAlgSHA1):@[@{@"key":[NSData dataFromHexString:@"95273b071820f54ed10df47458997e5188821e0073579cdfc097426cdbc947d5"],@"data":[NSData dataFromHexString:@"303931363262383862636434343431333832353130313261633830653134343461383230323539617c312e317c6c6f67696e7c323031332d30312d30315431323a33343a35365a7c2d2de6b8ace8a9a6e8b387e696992d2d"],@"correctHmac":@"6221bcbc273da52c746c0ce91025990626ef3338"}]};
    
       for (NSNumber *algorithmKey in testData) {
           for (NSDictionary *tData in testData[algorithmKey]) {
               
                NSData *key = tData[@"key"];
                NSData *data = tData[@"data"];
                
                
               CCHmacAlgorithm algorithm = [algorithmKey integerValue];
                NSString *hmacString = [[data HMACDataWithAlgorithm:algorithm  secret:key] HexString];
                NSString *correctHmac = tData[@"correctHmac"];
                if (![hmacString isEqualToString:correctHmac]) {
                    switch (algorithm) {
                        case kCCHmacAlgMD5:
                            NSLog(@"Algorithm: MD5");
                            break;
                        case kCCHmacAlgSHA1:
                            NSLog(@"Algorithm: SHA1");                            
                            break;
                        default:
                            break;
                    }
                    NSLog(@"hmac string:%@",hmacString);
                    NSLog(@"correct hmac string:%@",correctHmac);
                    
                    XCTFail(@"Hmac fail!");
                }
           }
       }
}
@end
