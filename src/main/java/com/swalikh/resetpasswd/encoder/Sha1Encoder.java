package com.swalikh.resetpasswd.encoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import sun.misc.BASE64Encoder;

public class Sha1Encoder {

    public static void main(String[] args) throws Exception {
        System.out.println(Sha1Encoder.encode("test", "123"));
    }

    public static String encode(String username, String password) throws NoSuchAlgorithmException{
        BASE64Encoder e = new BASE64Encoder();
        return username + ":{SHA}"  
                + e.encode(MessageDigest.getInstance("SHA1").digest(password.getBytes()));
    }
}
