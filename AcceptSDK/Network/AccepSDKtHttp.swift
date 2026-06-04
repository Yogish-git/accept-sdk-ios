
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
    // To obtain these hashes, use: openssl s_client -connect api.authorize.net:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    static let pinnedPublicKeyHashes: Set<String> = [
        // Primary certificate public key hash (Authorize.Net)
        // IMPORTANT: Replace these placeholder hashes with actual Authorize.Net certificate public key hashes
        // before deploying to production. Obtain current hashes using the openssl command above.
        "PLACEHOLDER_HASH_1_REPLACE_WITH_ACTUAL_HASH",
        // Backup certificate public key hash (for certificate rotation)
        "PLACEHOLDER_HASH_2_REPLACE_WITH_ACTUAL_HASH"
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
        var secResult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust, &secResult)

        guard status == errSecSuccess,
              secResult == .unspecified || secResult == .proceed else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Perform public key pinning validation
        if validatePinnedPublicKeys(serverTrust: serverTrust) {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - Public Key Pinning Validation

    private func validatePinnedPublicKeys(serverTrust: SecTrust) -> Bool {
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

            // Get the public key data
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                continue
            }

            // Calculate SHA-256 hash of the public key
            let publicKeyHash = sha256Hash(data: publicKeyData)

            // Check if this public key hash matches any of our pinned hashes
            if CertificatePinning.pinnedPublicKeyHashes.contains(publicKeyHash) {
                return true
            }
        }

        return false
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
