//
//  RSATools.h
//  RSA_DEMO
//
//  Created by 张昭 on 16/2/16.
//  Copyright © 2016年 张昭. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSATools : NSObject
/**
 *  Load pubilc key form file
 *
 *  @param derFilePath The path for public key
 */
- (void)loadPublicKeyFromFile:(NSString*)derFileName;


/**
 *  Load public key form data
 *
 *  @param derData The data for public key
 */
- (void)loadPublicKeyFromData:(NSData*)derData;

/**
 *  Load private key form file
 *
 *  @param p12FilePath The path for private key
 *  @param p12Password The password for private key
 */
- (void)loadPrivateKeyFromFile:(NSString*)p12FileName password:(NSString*)p12Password;

/**
 *  Load private key form data
 *
 *  @param p12Data The data for private key
 *  @param p12Password The password for private key
 */
- (void)loadPrivateKeyFromData:(NSData*)p12Data password:(NSString*)p12Password;

/**
 *  Return the SecKeyRef of public key
 *
 *  @param derData The data for public key
 *
 *  @return A SecKeyRef
 */
- (SecKeyRef)getPublicKeyRefrenceFromeData:(NSData*)derData;

/**
 *  Return the SecKeyRef of private key
 *
 *  @param p12Data  The data for private key
 *  @param password The password for private key
 *
 *  @return A SecKeyRef
 */
- (SecKeyRef)getPrivateKeyRefrenceFromData:(NSData*)p12Data password:(NSString*)password;

/**
 *  RSA encrypt with string
 *
 *  @param string The string for encrypt
 *
 *  @return The string of encrypted
 */
- (NSString*)rsaEncryptString:(NSString*)string;

/**
 *  RSA encrypt with data
 *
 *  @param data The data for encrypt
 *
 *  @return The data of encryted
 */
- (NSData*)rsaEncryptData:(NSData*)data;

/**
 *  RSA decrypt with string
 *
 *  @param string The string for decrypt
 *
 *  @return The string of decrypted
 */
- (NSString*)rsaDecryptString:(NSString*)string;

/**
 *  RSA decrypt with data
 *
 *  @param data The data for decrypt
 *
 *  @return The data of decrypted
 */
- (NSData*)rsaDecryptData:(NSData*)data;

/**
 *  Sign of sha 256
 *
 *  @param plainData  The data for sign
 *
 *  @return The data of signed
 */
- (NSData *)sha256WithRSA:(NSData *)plainData;

/**
 *  Sign of sha 256
 *
 *  @param plainData  The data for sign
 *  @param privateKey The private key for sign
 *
 *  @return The data of signed
 */
- (NSData *)sha256WithRSA:(NSData *)plainData privateKey:(SecKeyRef)privateKey;

/**
 *  Vertification of Sign 256
 *
 *  @param plainData The data for vertify
 *  @param signature The data of signed
 *
 *  @return Success of sha vertifying
 */
- (BOOL)rsaSHA256VertifyingData:(NSData *)plainData withSignature:(NSData *)signature;

/**
 *  Vertification of Sign 256
 *
 *  @param plainData The data for vertify
 *  @param signature The data of signed
 *  @param publicKey The public key for vertification
 *
 *  @return Success of sha vertifying
 */
- (BOOL)rsaSHA256VertifyingData:(NSData *)plainData withSignature:(NSData *)signature publicKey:(SecKeyRef)publicKey;

@end
