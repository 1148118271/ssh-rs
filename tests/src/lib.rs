
mod tests {
    use std::ptr;
    use std::str::FromStr;
    use aes::Aes128Ctr;
    use aes::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
    use aes::cipher::generic_array::GenericArray;
    use rsa::pkcs1::FromRsaPrivateKey;
    use rsa::{BigUint, PublicKeyParts};
    use rsa::pkcs8::ToPublicKey;

    #[test]
    fn f() {
        let ckey = [32_u8, 59, 160, 246, 139, 196, 208, 4, 112, 195, 76, 74, 254, 173, 172, 57];
        let civ  = [132_u8, 174, 184, 176, 168, 56, 129, 240, 56, 234, 129, 183, 8, 244, 32, 169];


        let mut buf = vec![0_u8, 0, 0, 92, 31, 50, 0, 0, 0, 4, 114, 111, 111, 116, 0, 0, 0, 14, 115, 115, 104, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 0, 0, 0, 8, 112, 97, 115, 115, 119, 111, 114, 100, 0, 0, 0, 0, 16, 71, 97, 111, 120, 105, 97, 110, 103, 107, 97, 110, 103, 64, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut buf_1 = vec![0_u8, 0, 0, 92, 31, 50, 0, 0, 0, 4, 114, 111, 111, 116, 0, 0, 0, 14, 115, 115, 104, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 0, 0, 0, 8, 112, 97, 115, 115, 119, 111, 114, 100, 0, 0, 0, 0, 16, 71, 97, 111, 120, 105, 97, 110, 103, 107, 97, 110, 103, 64, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let buf1 = [128_u8, 65, 115, 31, 142, 184, 153, 56, 41, 44, 69, 81, 33, 224, 22, 232, 212, 0, 23, 34, 104, 91, 193, 223, 60, 178, 115, 219, 134, 50, 35, 213, 201, 199, 227, 141, 179, 6, 164, 124, 52, 227, 48, 190, 130, 210, 112, 25, 89, 175, 211, 182, 170, 109, 18, 154, 51, 235, 20, 72, 36, 3, 31, 164, 23, 163, 186, 77, 213, 220, 15, 195, 222, 95, 64, 49, 134, 236, 42, 83, 149, 94, 68, 84, 187, 220, 159, 168, 181, 241, 49, 39, 83, 212, 31, 14];
        let buf2 = [128_u8, 65, 115, 31, 142, 184, 153, 56, 41, 44, 69, 81, 33, 224, 22, 232, 212, 0, 23, 34, 104, 91, 193, 223, 60, 178, 115, 219, 134, 50, 35, 213, 201, 199, 227, 141, 179, 6, 164, 124, 52, 227, 48, 190, 130, 210, 112, 25, 89, 175, 211, 182, 170, 109, 18, 154, 51, 235, 20, 72, 36, 3, 31, 164, 23, 163, 186, 77, 213, 220, 15, 195, 222, 95, 64, 49, 134, 236, 42, 83, 149, 94, 68, 84, 187, 220, 159, 168, 181, 241, 49, 39, 83, 212, 31, 14];

        let slice = GenericArray::from(ckey);
        let n = GenericArray::from(civ);
        let mut e = Aes128Ctr::new_from_slices(&slice, &n).unwrap();
        let mut d = Aes128Ctr::new_from_slices(&slice, &n).unwrap();



        println!("加密前 => {:?}", buf);
        e.apply_keystream(&mut buf);
        //e.seek(0);
        println!("加密后 => {:?}", buf);
        d.apply_keystream(&mut buf);
        //d.seek(0);
        println!("解密后 => {:?}", buf);

        println!("加密前 => {:?}", buf);
        e.apply_keystream(&mut buf);
        println!("加密后 => {:?}", buf);
        d.apply_keystream(&mut buf);
        println!("解密后 => {:?}", buf);
    }


    #[test]
    fn test2() {
        let bsize = 64;
        let data_len = 556;


        let mut padding_len = 8 - (data_len + 1) % 8;
        if padding_len < 4 { padding_len += 8 }

        //
        // let len = data_len + 5;
        // let mut pad = 4;
        // loop {
        //     if (len + pad) % bsize == 0 {
        //         break;
        //     }
        //     pad = pad + 1;
        // }


        println!("{}",  padding_len + 1 + 5 + 3)

    }


    #[test]
    fn test3() {
        let res_base64 = r#"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"#;


        // let result = base64::decode(res_base64);
        // println!("{:?}", result);

       // rsa::RsaPrivateKey::
        // ssh_key::PrivateKey::from()
        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(res_base64).unwrap();
        let key = rprk.to_public_key();
        let string = key.to_public_key_pem().unwrap();
        println!("{:?}", string)
        // let e = key.e();
        // let vec = e.to_bytes_be();
        // println!("{}", vec[0] & 0x80);
        // //println!("e => {:?}", e.to_bytes_le());
        // let n = key.n();
        // let vec = n.to_bytes_be();
        // i32::from_be_bytes(v)
        // let uint = BigUint::from_bytes_be(vec.as_slice());
        // println!("{:?}", uint)
        // println!("{}", (vec[0] & 0x80);


        // println!("n => {:?}", n.to_bytes_be());

        // let prk = PrivateKey::from_str(res_base64).unwrap();
        // let puk = prk.public_key();


        // let algorithm = prk.algorithm();
        // let str = algorithm.as_str();
        // println!("{:?}", puk)
    }

    #[test] fn t4() {
        let mut s = String::from("hhh");

        unsafe {
            let mut s2 = ptr::read(&s);
            println!("{:?}", s.as_ptr());
            println!("{:?}", s2.as_ptr());

            println!("{:?}", s);
            println!("{:?}", s2);


            s2 = String::default();

            s = String::from("bar");

            println!("{:?}", s.as_ptr());
            println!("{:?}", s2.as_ptr());

            println!("{:?}", s);
            println!("{:?}", s2);
        };

    }
}



