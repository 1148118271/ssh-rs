
mod tests {
    use aes::Aes128Ctr;
    use aes::cipher::{NewCipher, StreamCipher};
    use aes::cipher::generic_array::GenericArray;

    #[test]
    fn f() {
        let bs = b"abcdefjhrjkmsdfe";

        let mut k = [0u8; 16];
        let mut iv = [0u8; 16];
        k.clone_from_slice(bs);
        iv.clone_from_slice(bs);

        let slice = GenericArray::from(k);
        let n = GenericArray::from(iv);
        let mut result = Aes128Ctr::new_from_slices(&slice, &n).unwrap();
        let mut data = "abcdefjhrjkmsdfe".as_bytes().to_vec();
        result.apply_keystream(&mut data);

        // 57db78e0dabc1c0bb87cca69fa041b1e
        // 57db78e0dabc1c0bb87cca69fa041b1e
        //

        // let e = hex::encode(data);
        //

        println!("{:?}", base64::encode(data));


        // let string = hex::encode("0000000000000000");
        // println!("{}", string);

        // c96c4f5b291b128fcecd2b47a903cbcc
        // c96c4f5b291b128fcecd2b47a903cbcc
        // c96c4f5b291b128fcecd2b47a903cbcc



        // let slice = GenericArray::from([0u8; 16]);
        // let mut ctr = Aes128Ctr::new(&key, &slice);
        // let mut data = b"0000000000000000".to_vec();
        // let vec = data.clone();
        // // let mut data = String::from("123456").as_bytes();
        // // let mut result1 = hex::decode("c96c4f5b291b128fcecd2b47a903cbcc".as_bytes()).unwrap();
        // //println!("data: {:?}", data);
        // let array = Block::from([0u8; 16]);
        // ctr.apply_keystream(&mut data);
        //
        // ctr.apply_keystream(&mut data);
        //
        // println!("data: {:?}", data);
        // println!("data: {:?}", vec);
       // println!("data: {:?}", String::from_utf8(data));
        //let result = hex::encode(data);

        //println!("result: {:?}", result);
    }
}


