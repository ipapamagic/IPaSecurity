//import UIKit
//import XCTest
//import IPaSecurity
//
//class Tests: XCTestCase {
//    
//    override func setUp() {
//        super.setUp()
//        // Put setup code here. This method is called before the invocation of each test method in the class.
//    }
//    
//    override func tearDown() {
//        // Put teardown code here. This method is called after the invocation of each test method in the class.
//        super.tearDown()
//    }
//    
//    func testPerformanceExample() {
//        // This is an example of a performance test case.
//        self.measure {
//            // Put the code you want to measure the time of here.
//        }
//    }
//    //MARK : XCTestCase
//    func testSHA256()
//    {
//        let testCase = [
//            "ROCK":"5adfabaf0034944241e990102d633da1570763930acbb84213b8552bd393a17c",
//            "RACK":"24f13e344a25bc712673222c17042a71d5860f0ad0b2acb23cac226880993608",
//            "ROCKY":"8fb0c6406e29577e4908d5ba5bc35ec98b08cec26debf76c3d6ecf88774bf264",
//            "Rock'S saying":"48c7c57ca89c80fe1f0e0759c833b7b8c9cde6ac8fe42675c9299534c083e772"]
//        for key in testCase.keys {
//            guard let result = key.sha256String,let realResult = testCase[key] else {
//                XCTFail("key with sha256 fail")
//                return
//            }
//            
//            XCTAssert(result == realResult,"SHA256 fail! result not correct")
//            
//        }
//    }
//    func testSHA1()
//    {
//        let testCase =  [ "ROCK":"8f97f5a81bc2a63f2e65b956b0cd5ac334284509",
//                          "RACK":"ac61253a34bf8d851a1e251d0fa4856527feaa88",
//                          "ROCKY":"99457410e3c1857f33279f23781ed6ebc93deb4c",
//                          "Rock'S saying":"a60cee862827c2fc45cb4a7f285f6bfba1a643e8"]
//        
//        for key in testCase.keys {
//            guard let result = key.sha1String,let realResult = testCase[key] else {
//                XCTFail("key with sha1 fail")
//                return
//            }
//            
//            XCTAssert(result == realResult,"SHA1 fail! result not correct")
//            
//        }
//        
//        let data = Data(hexString: "a0b1c2d3e4f5")
//        let string = data.sha1String
//        XCTAssert(string == "09162b88bcd444138251012ac80e1444a820259a","SHA1 fail! result not correct")
//        
//        
//        
//    }
//    func testMD5()
//    {
//        
//        let testCase = ["ROCK":"afeb717aa2a101f7f64840e0be38c171",
//                        "RACK":"1ece4bad0efe8b897c6e7f8bd101759f",
//                        "ROCKY":"6cd910740cbbbbd0f55238a93fba157d",
//                        "Rock'S saying":"7dca0df0dfa7f76b652e53daa4852640"]
//        
//        for key in testCase.keys {
//            guard let result = key.md5String,let realResult = testCase[key] else {
//                XCTFail("key with MD5 fail")
//                return
//            }
//            
//            XCTAssert(result == realResult,"MD5 fail! result not correct")
//            
//        }
//    }
//    func subTaskHKDF(algorithm:CCHmacAlgorithm,testData:[[String:Any]]) {
//        for data in testData {
//            guard let hexIKM = data["IKM"] as? String ,let length = data["length"] as? Int ,let hexRealOKM = data["realOKM"] as? String else {
//                XCTFail("HKDF testCase data fail")
//                return
//            }
//            var salt:Data?
//            var info:Data?
//            if let hexSalt = data["salt"] as? String {
//                salt = Data(hexString:hexSalt)
//            }
//            
//            let IKM = Data(hexString:hexIKM)
//            if let hexRealPRK = data["realPRK"] as? String  {
//                
//                let PRK = IKM.hmacData(algorithm:algorithm,secret:salt).hexString
//                print("PRK:\(PRK)")
//                print("realPRK:\(hexRealPRK)")
//                XCTAssert(PRK == hexRealPRK, "HKDF fail!! PRK not correct!")
//            }
//            if let hexInfo = data["info"] as? String {
//                info = Data(hexString:hexInfo)
//            }
//            guard let OKMData = IKM.hkdfData(algorithm: algorithm, info: info, length: length, salt: salt) else {
//                XCTFail("OKM fail!")
//                return
//            }
//            let OKM = OKMData.hexString
//            
//            print("OKM:\(OKM)")
//            print("realOKM:\(hexRealOKM)")
//            XCTAssert(OKM == hexRealOKM, "HKDF fail!! OKM not correct!")
//        }
//    }
//    func testHKDF()
//    {
//        let sha256testData = [["IKM": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
//                               "salt":"000102030405060708090a0b0c",
//                               "info":"f0f1f2f3f4f5f6f7f8f9",
//                               "realPRK":"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
//                               "realOKM":"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
//                               "length":42],
//                              ["IKM": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
//                               "salt":"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
//                               "info":"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
//                               "realPRK":"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
//                               "realOKM":"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
//                               "length":82],
//                              ["IKM": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
//                               
//                               "realPRK":"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
//                               "realOKM":"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
//                               "length":42],
//                              ["IKM":"a0a1a2a3a4a5a6a7b0b1b2b3b4b5b6b7c0c1c2c3c4c5c6c7d0d1d2d3d4d5d6d7",
//                               "info":"09162b88bcd444138251012ac80e1444a820259a",
//                               "realOKM":"95273b071820f54ed10df47458997e5188821e0073579cdfc097426cdbc947d5","length":32]]
//        
//        subTaskHKDF(algorithm:CCHmacAlgorithm(kCCHmacAlgSHA256),testData: sha256testData)
//        
//        
//        let sha1testData = [["IKM": "0b0b0b0b0b0b0b0b0b0b0b",
//                             "salt":"000102030405060708090a0b0c",
//                             "info":"f0f1f2f3f4f5f6f7f8f9",
//                             "realPRK":"9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
//                             "realOKM":"085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
//                             "length":42],
//                            ["IKM": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
//                             "salt":"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
//                             "info":"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
//                             "realPRK":"8adae09a2a307059478d309b26c4115a224cfaf6",
//                             "realOKM":"0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
//                             "length":82],
//                            ["IKM": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
//                             
//                             "realPRK":"da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
//                             "realOKM":"0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
//                             "length":42],
//                            ["IKM": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
//                             
//                             "realPRK":"2adccada18779e7c2077ad2eb19d3f3e731385dd",
//                             "realOKM":"2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
//                             "length":42]]
//        subTaskHKDF(algorithm:CCHmacAlgorithm(kCCHmacAlgSHA1),testData: sha1testData)
//        
//    }
//    
//}
//
