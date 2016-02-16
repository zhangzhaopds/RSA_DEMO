//
//  ViewController.m
//  RSA_DEMO
//
//  Created by 张昭 on 16/2/16.
//  Copyright © 2016年 张昭. All rights reserved.
//

#import "ViewController.h"
#import "RSATools.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    RSATools *rsa = [[RSATools alloc] init];
    [rsa loadPublicKeyFromFile:@"public_key.der"];
    
    // .p12 或者 .pfx 都能用作密钥的载体，效果相同
    [rsa loadPrivateKeyFromFile:@"private_key.pfx" password:@"999"];
#if 0
    [rsa loadPrivateKeyFromFile:@"private_key.p12" password:@"000"];
#endif
    
    NSString *str = [rsa rsaEncryptString:@"真好"];
    NSLog(@"加密：%@", str);
    NSString *stt = [rsa rsaDecryptString:str];
    NSLog(@"解密：%@", stt);
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
