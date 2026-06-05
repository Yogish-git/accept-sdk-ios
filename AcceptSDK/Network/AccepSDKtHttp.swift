
//
//  IAPHttp.swift
//  AcceptSDK
//
//  Created by Ramamurthy, Rakesh Ramamurthy on 7/11/16.
//  Copyright © 2016 Ramamurthy, Rakesh Ramamurthy. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

let HTTP_TIMEOUT = TimeInterval(30)

// MARK: - Certificate Pinning Configuration
private struct CertificatePinning {
    // Allowed hostnames for Authorize.Net
    static let allowedHosts = [
        "api.authorize.net",
        "apitest.authorize.net"
    ]

    // SHA-256 hashes of the Subject Public Key Info (SPKI) for Authorize.Net certificates
    // These should be updated when Authorize.Net rotates their certificates
    // To obtain these hashes, use:
    // openssl s_client -connect api.authorize.net:443 -servername api.authorize.net 2>/dev/null | \
    //   openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    static let pinnedPublicKeyHashes: Set<String> = [
        // Authorize.Net leaf certificate public key hash (api.authorize.net / apitest.authorize.net)
        "cLXQh6iGA40oLXrKrnJHkf+JkZ94NnwC+JpvQ2pHifo=",
        // Intermediate CA certificate public key hash (backup pin for certificate rotation)
        "mombFYgkelED1OHDVo8RitQHj447/vhd9x9eMEJygkg="
    ]

    // ASN.1 header for RSA 2048-bit public key SPKI encoding
    // This header is prepended to raw public key bytes to create proper SPKI DER format
    // Format: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { public key } }
    static let rsa2048SPKIHeader: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    // ASN.1 header for RSA 4096-bit public key SPKI encoding
    static let rsa4096SPKIHeader: [UInt8] = [
        0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
    ]

    // ASN.1 header for EC P-256 public key SPKI encoding
    static let ecdsaSecp256r1SPKIHeader: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    ]

    // ASN.1 header for EC P-384 public key SPKI encoding
    static let ecdsaSecp384r1SPKIHeader: [UInt8] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
        0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
    ]
}

private struct HTTPStatusCode {
    static let kHTTPSuccessCode         = 200
    static let kHTTPCreationSuccessCode = 201
}

class HttpRequest {
    var method : String?
    var url : String?
    var httpHeaders : Dictionary <String, AnyObject>?
    var bodyParameters: String?
    
    init(httMethod : String, url : String, httpHeaders : Dictionary <String, AnyObject>?, bodyParameters : String?){
        self.method = httMethod
        self.url = url
        
        if let parameters = httpHeaders {
            self.httpHeaders = parameters
        }
        
        if let parameters = bodyParameters {
            self.bodyParameters = parameters
        }
    }
    
    internal func urlRequest () -> NSMutableURLRequest {
        let result = NSMutableURLRequest(url: URL(string: self.url!)!)
//        result.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        result.setValue("application/json", forHTTPHeaderField: "Accept")
        result.timeoutInterval = HTTP_TIMEOUT
        result.httpMethod = self.method!
        
        if let parameters = self.bodyParameters {
            result.setBodyContent(parameters)
        }

        if let parameters = self.httpHeaders {
            for (headerField, value) in parameters {
                result.setValue(value as? String, forHTTPHeaderField: headerField)
            }
        }
        
        return result
    }
}

private struct HTTPErrorKeys {
    static let kErrorsKey = "errors"
    static let kErrorTypeKey = "type"
    static let kErrorMessageKey = "message"
}

struct HTTPErrorResponseCode {
    static let apiErrorResponseCode = 4000
    static let kErrorDictionaryKey  = "Error_Info_Dict"
}

class HTTPResponse {
    var code : Int?
    var body : Dictionary <String, AnyObject>?
    var error : NSError?
    
    init () {
    }
}

class HTTP: NSObject, URLSessionDelegate {

    func request(_ request : HttpRequest) -> HTTPResponse {

        let urlRequest : NSMutableURLRequest = request.urlRequest()

        return self.requestSynchronousData(urlRequest as URLRequest)

    }

    // MARK: - URLSessionDelegate Certificate Pinning

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        // Only handle server trust authentication
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let host = challenge.protectionSpace.host

        // Verify the host is one of our allowed Authorize.Net hosts
        guard CertificatePinning.allowedHosts.contains(host) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Perform standard SSL validation first
        if #available(iOS 12.0, *) {
            var error: CFError?
            let isValid = SecTrustEvaluateWithError(serverTrust, &error)
            guard isValid, error == nil else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        } else {
            // Fallback for iOS < 12.0: use deprecated but functional SecTrustEvaluate
            var secResult = SecTrustResultType.invalid
            let status = SecTrustEvaluate(serverTrust, &secResult)
            guard status == errSecSuccess,
                  secResult == .unspecified || secResult == .proceed else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        // Perform public key pinning validation
        if validatePinnedPublicKeys(serverTrust: serverTrust) {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            // Fail closed: reject connection if pinning validation fails
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - Public Key Pinning Validation

    private func validatePinnedPublicKeys(serverTrust: SecTrust) -> Bool {
        // iOS 12.0+ required for SecCertificateCopyKey
        // For older iOS versions, fail closed (reject connection) for security
        guard #available(iOS 12.0, *) else {
            // Fail closed on older iOS versions that don't support required Security APIs
            // This ensures no unvalidated connections are allowed
            return false
        }

        let certificateCount = SecTrustGetCertificateCount(serverTrust)

        // Check each certificate in the chain
        for index in 0..<certificateCount {
            guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, index) else {
                continue
            }

            // Extract the public key from the certificate
            guard let publicKey = SecCertificateCopyKey(certificate) else {
                continue
            }

            // Get the raw public key data
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                continue
            }

            // Get the key type and size to determine correct SPKI header
            guard let keyAttributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
                  let keyType = keyAttributes[kSecAttrKeyType as String] as? String,
                  let keySize = keyAttributes[kSecAttrKeySizeInBits as String] as? Int else {
                continue
            }

            // Construct full SPKI DER by prepending appropriate ASN.1 header to raw key bytes
            let spkiData = constructSPKIData(publicKeyData: publicKeyData, keyType: keyType, keySize: keySize)

            // Calculate SHA-256 hash of the full SPKI DER
            let publicKeyHash = sha256Hash(data: spkiData)

            // Check if this public key hash matches any of our pinned hashes
            if CertificatePinning.pinnedPublicKeyHashes.contains(publicKeyHash) {
                return true
            }
        }

        return false
    }

    /// Constructs Subject Public Key Info (SPKI) DER format by prepending the appropriate
    /// ASN.1 header to raw public key bytes. This matches the format produced by:
    /// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der`
    private func constructSPKIData(publicKeyData: Data, keyType: String, keySize: Int) -> Data {
        var spkiHeader: [UInt8]

        if keyType == (kSecAttrKeyTypeRSA as String) {
            switch keySize {
            case 2048:
                spkiHeader = CertificatePinning.rsa2048SPKIHeader
            case 4096:
                spkiHeader = CertificatePinning.rsa4096SPKIHeader
            default:
                // Unknown RSA key size - return raw data (will fail pinning check safely)
                return publicKeyData
            }
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            switch keySize {
            case 256:
                spkiHeader = CertificatePinning.ecdsaSecp256r1SPKIHeader
            case 384:
                spkiHeader = CertificatePinning.ecdsaSecp384r1SPKIHeader
            default:
                // Unknown EC key size - return raw data (will fail pinning check safely)
                return publicKeyData
            }
        } else {
            // Unknown key type - return raw data (will fail pinning check safely)
            return publicKeyData
        }

        // Prepend SPKI header to raw public key data
        var spkiData = Data(spkiHeader)
        spkiData.append(publicKeyData)
        return spkiData
    }

    private func sha256Hash(data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
    
    fileprivate func requestSynchronousData(_ request: URLRequest) -> HTTPResponse {
        let httpResponse = HTTPResponse()
        
        let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
        
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        let session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: nil)
        
        let task = session.dataTask(with: request, completionHandler: {
            taskData, response, error -> () in
            if (error != nil) {
                httpResponse.error = error as NSError?
            }
            else if let castedResponse = response as? HTTPURLResponse {
                let bodyDict = self.deserializeData(taskData!)
                
                if HTTPStatusCode.kHTTPSuccessCode == castedResponse.statusCode || HTTPStatusCode.kHTTPCreationSuccessCode == castedResponse.statusCode {
                    httpResponse.body = bodyDict
                } else {
                    let (errorMessage) = self.getErrorResponse(bodyDict!)
                    if let message = errorMessage {
                        httpResponse.error = NSError(domain: message, code: castedResponse.statusCode, userInfo:[NSLocalizedDescriptionKey:message,HTTPErrorResponseCode.kErrorDictionaryKey:bodyDict!])
                    }else {
                        httpResponse.error = NSError(domain: "BadResponse", code: castedResponse.statusCode, userInfo:nil)
                    }
                }
            }
            
            semaphore.signal();
        })
        task.resume()
        _ = semaphore.wait(timeout: DispatchTime.distantFuture)
        return httpResponse
    }

    fileprivate func getErrorResponse(_ responseDict:Dictionary<String, AnyObject>)->String? {
        var errorMessage:String?
        if  let errorArray = responseDict[HTTPErrorKeys.kErrorsKey] as? [[String:String]] {
            if let error = errorArray.first {
                errorMessage = error[HTTPErrorKeys.kErrorMessageKey]
            }
        }
        return errorMessage
    }

    fileprivate func serializeJson (_ json : Dictionary <String, AnyObject>) -> Data? {
        let result : Data? = try! JSONSerialization.data(withJSONObject: json, options: [])
        
        return result;
    }
    
    fileprivate func deserializeData (_ data : Data) -> Dictionary<String, AnyObject>? {
        var jsonDict:Dictionary<String, AnyObject> = [:]
        do{
            jsonDict = try JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers) as! Dictionary<String, AnyObject>
        }
        catch _ as NSError{
            //todo handle error
        }
        return jsonDict
        
    }
}

extension NSMutableURLRequest {
    @objc func setBodyContent(_ contentStr: String?) {
        self.httpBody = contentStr!.data(using: String.Encoding.utf8)
    }
}
