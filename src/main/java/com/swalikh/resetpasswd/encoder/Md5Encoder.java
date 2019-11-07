package com.swalikh.resetpasswd.encoder;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Md5Encoder {

    public static void main(String[] args) throws Exception {
        String test = Md5Encoder.encode("test", "123");
        System.err.println("原密码密文为：\t" + test);
        System.err.println("盐值为：\t" + getSalt(test));
        System.err.println("明文加盐值生成密文：\t" + encodeByWithSalt("test", "123", getSalt(test)));

    }

    private static int hexcase = 0; /* hex output format. 0 - lowercase; 1 -  uppercase*/
    private static String b64pad = "=";/* base-64 pad character. "=" for strict RFC compliance*/
    private static int chrsz = 8; /* bits per input character. 8 - ASCII; 16 - Unicode*/
    private static String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static String hex_md5(String s) {
        return binl2hex(core_md5(str2binl(s), s.length() * chrsz));
    }

    private static String b64_md5(String s) {
        return binl2b64(core_md5(str2binl(s), s.length() * chrsz));
    }

    private static String str_md5(String s) {
        int[] a1 = str2binl(s);
        int[] a = core_md5(a1, s.length() * chrsz);
        String str = binl2str(a);
        return str;
    }

    private static String hex_hmac_md5(String key, String data) {
        return binl2hex(core_hmac_md5(key, data));
    }

    private static String b64_hmac_md5(String key, String data) {
        return binl2b64(core_hmac_md5(key, data));
    }

    private static String str_hmac_md5(String key, String data) {
        return binl2str(core_hmac_md5(key, data));
    }

    /*
     * Calculate the MD5 of an array of little-endian words, and a bit length
     */
    private static int[] core_md5(int[] x, int len) {
        Map<String, String> m = new HashMap<String, String>();
        for (int i = 0; i < x.length; i++) {
            m.put(i + "", String.valueOf(x[i]));
        }
        /* append padding */
        int k = len >> 5;
        // x[len >> 5] |= 0x80 << ((len) % 32);
        int value5 = 0x80 << ((len) % 32);
        m.put(k + "",
                String.valueOf((!m.containsKey(k + "") ? 0 : Integer.parseInt(m
                        .get(k + ""))) | value5));
        // x[(((len + 64) >>> 9) << 4) + 14] = len;
        k = (((len + 64) >>> 9) << 4) + 14;
        m.put(k + "", String.valueOf(len));
        int a = 1732584193;
        int b = -271733879;
        int c = -1732584194;
        int d = 271733878;
        for (int i = 0; i < k + 1; i += 16) {
            int olda = a;
            int oldb = b;
            int oldc = c;
            int oldd = d;

            a = md5_ff(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 0 + "") ? 0 : Integer.parseInt(m.get(i
                            + 0 + "")), 7, -680876936);
            d = md5_ff(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 1 + "") ? 0 : Integer.parseInt(m.get(i
                            + 1 + "")), 12, -389564586);
            c = md5_ff(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 2 + "") ? 0 : Integer.parseInt(m.get(i
                            + 2 + "")), 17, 606105819);
            b = md5_ff(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 3 + "") ? 0 : Integer.parseInt(m.get(i
                            + 3 + "")), 22, -1044525330);
            a = md5_ff(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 4 + "") ? 0 : Integer.parseInt(m.get(i
                            + 4 + "")), 7, -176418897);
            d = md5_ff(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 5 + "") ? 0 : Integer.parseInt(m.get(i
                            + 5 + "")), 12, 1200080426);
            c = md5_ff(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 6 + "") ? 0 : Integer.parseInt(m.get(i
                            + 6 + "")), 17, -1473231341);
            b = md5_ff(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 7 + "") ? 0 : Integer.parseInt(m.get(i
                            + 7 + "")), 22, -45705983);
            a = md5_ff(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 8 + "") ? 0 : Integer.parseInt(m.get(i
                            + 8 + "")), 7, 1770035416);
            d = md5_ff(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 9 + "") ? 0 : Integer.parseInt(m.get(i
                            + 9 + "")), 12, -1958414417);
            c = md5_ff(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 10 + "") ? 0 : Integer.parseInt(m.get(i
                            + 10 + "")), 17, -42063);
            b = md5_ff(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 11 + "") ? 0 : Integer.parseInt(m.get(i
                            + 11 + "")), 22, -1990404162);
            a = md5_ff(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 12 + "") ? 0 : Integer.parseInt(m.get(i
                            + 12 + "")), 7, 1804603682);
            d = md5_ff(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 13 + "") ? 0 : Integer.parseInt(m.get(i
                            + 13 + "")), 12, -40341101);
            c = md5_ff(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 14 + "") ? 0 : Integer.parseInt(m.get(i
                            + 14 + "")), 17, -1502002290);
            b = md5_ff(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 15 + "") ? 0 : Integer.parseInt(m.get(i
                            + 15 + "")), 22, 1236535329);

            a = md5_gg(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 1 + "") ? 0 : Integer.parseInt(m.get(i
                            + 1 + "")), 5, -165796510);
            d = md5_gg(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 6 + "") ? 0 : Integer.parseInt(m.get(i
                            + 6 + "")), 9, -1069501632);
            c = md5_gg(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 11 + "") ? 0 : Integer.parseInt(m.get(i
                            + 11 + "")), 14, 643717713);
            b = md5_gg(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 0 + "") ? 0 : Integer.parseInt(m.get(i
                            + 0 + "")), 20, -373897302);
            a = md5_gg(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 5 + "") ? 0 : Integer.parseInt(m.get(i
                            + 5 + "")), 5, -701558691);
            d = md5_gg(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 10 + "") ? 0 : Integer.parseInt(m.get(i
                            + 10 + "")), 9, 38016083);
            c = md5_gg(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 15 + "") ? 0 : Integer.parseInt(m.get(i
                            + 15 + "")), 14, -660478335);
            b = md5_gg(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 4 + "") ? 0 : Integer.parseInt(m.get(i
                            + 4 + "")), 20, -405537848);
            a = md5_gg(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 9 + "") ? 0 : Integer.parseInt(m.get(i
                            + 9 + "")), 5, 568446438);
            d = md5_gg(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 14 + "") ? 0 : Integer.parseInt(m.get(i
                            + 14 + "")), 9, -1019803690);
            c = md5_gg(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 3 + "") ? 0 : Integer.parseInt(m.get(i
                            + 3 + "")), 14, -187363961);
            b = md5_gg(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 8 + "") ? 0 : Integer.parseInt(m.get(i
                            + 8 + "")), 20, 1163531501);
            a = md5_gg(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 13 + "") ? 0 : Integer.parseInt(m.get(i
                            + 13 + "")), 5, -1444681467);
            d = md5_gg(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 2 + "") ? 0 : Integer.parseInt(m.get(i
                            + 2 + "")), 9, -51403784);
            c = md5_gg(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 7 + "") ? 0 : Integer.parseInt(m.get(i
                            + 7 + "")), 14, 1735328473);
            b = md5_gg(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 12 + "") ? 0 : Integer.parseInt(m.get(i
                            + 12 + "")), 20, -1926607734);

            a = md5_hh(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 5 + "") ? 0 : Integer.parseInt(m.get(i
                            + 5 + "")), 4, -378558);
            d = md5_hh(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 8 + "") ? 0 : Integer.parseInt(m.get(i
                            + 8 + "")), 11, -2022574463);
            c = md5_hh(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 11 + "") ? 0 : Integer.parseInt(m.get(i
                            + 11 + "")), 16, 1839030562);
            b = md5_hh(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 14 + "") ? 0 : Integer.parseInt(m.get(i
                            + 14 + "")), 23, -35309556);
            a = md5_hh(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 1 + "") ? 0 : Integer.parseInt(m.get(i
                            + 1 + "")), 4, -1530992060);
            d = md5_hh(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 4 + "") ? 0 : Integer.parseInt(m.get(i
                            + 4 + "")), 11, 1272893353);
            c = md5_hh(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 7 + "") ? 0 : Integer.parseInt(m.get(i
                            + 7 + "")), 16, -155497632);
            b = md5_hh(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 10 + "") ? 0 : Integer.parseInt(m.get(i
                            + 10 + "")), 23, -1094730640);
            a = md5_hh(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 13 + "") ? 0 : Integer.parseInt(m.get(i
                            + 13 + "")), 4, 681279174);
            d = md5_hh(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 0 + "") ? 0 : Integer.parseInt(m.get(i
                            + 0 + "")), 11, -358537222);
            c = md5_hh(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 3 + "") ? 0 : Integer.parseInt(m.get(i
                            + 3 + "")), 16, -722521979);
            b = md5_hh(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 6 + "") ? 0 : Integer.parseInt(m.get(i
                            + 6 + "")), 23, 76029189);
            a = md5_hh(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 9 + "") ? 0 : Integer.parseInt(m.get(i
                            + 9 + "")), 4, -640364487);
            d = md5_hh(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 12 + "") ? 0 : Integer.parseInt(m.get(i
                            + 12 + "")), 11, -421815835);
            c = md5_hh(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 15 + "") ? 0 : Integer.parseInt(m.get(i
                            + 15 + "")), 16, 530742520);
            b = md5_hh(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 2 + "") ? 0 : Integer.parseInt(m.get(i
                            + 2 + "")), 23, -995338651);

            a = md5_ii(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 0 + "") ? 0 : Integer.parseInt(m.get(i
                            + 0 + "")), 6, -198630844);
            d = md5_ii(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 7 + "") ? 0 : Integer.parseInt(m.get(i
                            + 7 + "")), 10, 1126891415);
            c = md5_ii(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 14 + "") ? 0 : Integer.parseInt(m.get(i
                            + 14 + "")), 15, -1416354905);
            b = md5_ii(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 5 + "") ? 0 : Integer.parseInt(m.get(i
                            + 5 + "")), 21, -57434055);
            a = md5_ii(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 12 + "") ? 0 : Integer.parseInt(m.get(i
                            + 12 + "")), 6, 1700485571);
            d = md5_ii(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 3 + "") ? 0 : Integer.parseInt(m.get(i
                            + 3 + "")), 10, -1894986606);
            c = md5_ii(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 10 + "") ? 0 : Integer.parseInt(m.get(i
                            + 10 + "")), 15, -1051523);
            b = md5_ii(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 1 + "") ? 0 : Integer.parseInt(m.get(i
                            + 1 + "")), 21, -2054922799);
            a = md5_ii(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 8 + "") ? 0 : Integer.parseInt(m.get(i
                            + 8 + "")), 6, 1873313359);
            d = md5_ii(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 15 + "") ? 0 : Integer.parseInt(m.get(i
                            + 15 + "")), 10, -30611744);
            c = md5_ii(
                    c,
                    d,
                    a,
                    b,
                    !m.containsKey(i + 6 + "") ? 0 : Integer.parseInt(m.get(i
                            + 6 + "")), 15, -1560198380);
            b = md5_ii(
                    b,
                    c,
                    d,
                    a,
                    !m.containsKey(i + 13 + "") ? 0 : Integer.parseInt(m.get(i
                            + 13 + "")), 21, 1309151649);
            a = md5_ii(
                    a,
                    b,
                    c,
                    d,
                    !m.containsKey(i + 4 + "") ? 0 : Integer.parseInt(m.get(i
                            + 4 + "")), 6, -145523070);
            d = md5_ii(
                    d,
                    a,
                    b,
                    c,
                    !m.containsKey(i + 11 + "") ? 0 : Integer.parseInt(m.get(i
                            + 11 + "")), 10, -1120210379);
            c = md5_ii(c, d, a, b,
                    !m.containsKey(i + 2 + "") ? 0 : Integer.parseInt(m.get(i
                            + 2 + "")), 15, 718787259);
            b = md5_ii( b, c, d, a,
                    !m.containsKey(i + 9 + "") ? 0 : Integer.parseInt(m.get(i
                            + 9 + "")), 21, -343485551);

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
        }
        return new int[] { a, b, c, d };

    }

    /*
     * These functions implement the four basic operations the algorithm uses.
     */
    private static int md5_cmn(int q, int a, int b, int x, int s, int t) {
        return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
    }

    private static int md5_ff(int a, int b, int c, int d, int x, int s, int t) {
        return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }

    private static int md5_gg(int a, int b, int c, int d, int x, int s, int t) {
        return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }

    private static int md5_hh(int a, int b, int c, int d, int x, int s, int t) {
        return md5_cmn(b ^ c ^ d, a, b, x, s, t);
    }

    private static int md5_ii(int a, int b, int c, int d, int x, int s, int t) {
        return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    /*
     * Calculate the HMAC-MD5, of a key and some data
     */
    private static int[] core_hmac_md5(String key, String data) {
        int[] bkey = str2binl(key);
        if (bkey.length > 16)
            bkey = core_md5(bkey, key.length() * chrsz);

        int[] ipad = new int[16], opad = new int[16];
        for (int i = 0; i < 16; i++) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }
        String hmac = binl2str(ipad).concat(data);
        int[] hmac_int = str2binl(hmac);
        int[] hash = core_md5(hmac_int, 512 + data.length() * chrsz);
        return core_md5(str2binl(binl2str(opad).concat(binl2str(hash))),
                512 + 128);
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally to
     * work around bugs in some JS interpreters.
     */
    private static int safe_add(int x, int y) {
        int lsw = (x & 0xFFFF) + (y & 0xFFFF);
        int msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    private static int bit_rol(int num, int cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
     * Convert a string to an array of little-endian words If chrsz is ASCII,
     * characters >255 have their hi-byte silently ignored.
     */
    private static int[] str2binl(String str) {
        Map<String, Integer> m = new HashMap<String, Integer>();
        int mask = (1 << chrsz) - 1;
        for (int i = 0; i < str.length() * chrsz; i += chrsz) {
            int ifg = i >> 5;
            // bin[i>>5] |= (str.codePointAt(i / chrsz) & mask) << (i%32);
            m.put(ifg + "",
                    ((!m.containsKey(ifg + "") ? 0 : m.get(ifg + "")) | ((str
                            .codePointAt(i / chrsz) & mask) << (i % 32))));
        }
        Set<String> keys = m.keySet();
        int[] bin = new int[keys.size()];
        for (String key : keys) {
            int index = Integer.parseInt(key);
            bin[index] = m.get(key);
        }
        return bin;
    }

    /*
     * Convert an array of little-endian words to a string
     */
    private static String binl2str(int[] bin) {
        String str = "";
        int mask = (1 << chrsz) - 1;
        for (int i = 0; i < bin.length * 32; i += chrsz)
            str += (char) ((bin[i >> 5] >>> (i % 32)) & mask);
        return str;
    }

    /*
     * Convert an array of little-endian words to a hex string.
     */
    private static String binl2hex(int[] binarray) {
        String hex_tab = hexcase == 1 ? "0123456789ABCDEF" : "0123456789abcdef";
        String str = "";
        for (int i = 0; i < binarray.length * 4; i++) {
            str += hex_tab
                    .charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF)
                    + hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
        }
        return str;
    }

    /*
     * Convert an array of little-endian words to a base-64 string
     */
    private static String binl2b64(int[] binarray) {
        String tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        String str = "";
        for (int i = 0; i < binarray.length * 4; i += 3) {
            int triplet = (((binarray[i >> 2] >> 8 * (i % 4)) & 0xFF) << 16)
                    | (((binarray[i + 1 >> 2] >> 8 * ((i + 1) % 4)) & 0xFF) << 8)
                    | ((binarray[i + 2 >> 2] >> 8 * ((i + 2) % 4)) & 0xFF);
            for (int j = 0; j < 4; j++) {
                if (i * 8 + j * 6 > binarray.length * 32)
                    str += b64pad;
                else
                    str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
            }
        }
        return str;
    }

    private static String ap_to64(int v, int n) {
        String s = "";
        while (--n >= 0) {
            s += itoa64.charAt(v & 0x3f); // prend les 6 bits les plus à droite.
            v >>>= 6; // décale de 6 bits.
        }
        return s;
    }

    // Convertit une chaîne en tableau de codes ASCII.
    private static int[] stringToArray(String s) {
        int[] a = new int[s.length()];
        for (int i = 0; i < s.length(); i++)
            a[i] = (int) s.charAt(i);
        return a;
    }

    public static String encode(String username, String pwd) {
        String result = null;
        String cpw = "";
        String AP_MD5PW_ID = "$apr1$";
        String salt = ap_to64((int) Math.floor(Math.random() * 16777215), 4) // 2^24-1 : 4 * 6  bits.
                + ap_to64((int) Math.floor(Math.random() * 16777215), 4); // 2^24-1 : 4 * 6 bits.
        String msg = pwd + AP_MD5PW_ID + salt;
        String final_ = str_md5(pwd + salt + pwd);
        for (int pl = pwd.length(); pl > 0; pl -= 16)
            msg += final_.substring(0, (pl > 16) ? 16 : pl);
        /*
         * Then something really weird...
         */
        for (int i = pwd.length(); i != 0; i >>= 1)
            if ((i & 1) == 1) {
                msg += (char) 0;
            } else {
                msg += (char) pwd.charAt(0);
            }
        final_ = str_md5(msg);
        /*
         * Ensuite une partie pour ralenir les choses ! En JavaScript ça va être
         * vraiment lent !
         */
        String msg2;
        for (int i = 0; i < 1000; i++) {
            msg2 = "";
            if ((i & 1) == 1)
                msg2 += pwd;
            else
                msg2 += final_.substring(0, 16);
            if (i % 3 != 0)
                msg2 += salt;
            if (i % 7 != 0)
                msg2 += pwd;
            if ((i & 1) == 1) {
                msg2 += final_.substring(0, 16);
            } else {
                msg2 += pwd;
            }
            final_ = str_md5(msg2);
        }
        int[] _final = stringToArray(final_);

        /*
         * Now make the output string.
         */
        cpw = AP_MD5PW_ID + salt + '$';
        cpw += ap_to64((_final[0] << 16) | (_final[6] << 8) | _final[12], 4);
        cpw += ap_to64((_final[1] << 16) | (_final[7] << 8) | _final[13], 4);
        cpw += ap_to64((_final[2] << 16) | (_final[8] << 8) | _final[14], 4);
        cpw += ap_to64((_final[3] << 16) | (_final[9] << 8) | _final[15], 4);
        cpw += ap_to64((_final[4] << 16) | (_final[10] << 8) | _final[5], 4);
        cpw += ap_to64(_final[11], 2);
        
        if (username.length() + 1 + cpw.length() > 255)
            return null;
        result = cpw;
        return username + ":" + result;
    }

    public static String encodeByWithSalt(String username, String pwd,String origin) {
        String result = null;
        String cpw = "";
        String AP_MD5PW_ID = "$apr1$";
        String salt = origin;
        String msg = pwd + AP_MD5PW_ID + salt;
        String final_ = str_md5(pwd + salt + pwd);
        for (int pl = pwd.length(); pl > 0; pl -= 16)
            msg += final_.substring(0, (pl > 16) ? 16 : pl);
        /*
         * Then something really weird...
         */
        for (int i = pwd.length(); i != 0; i >>= 1)
            if ((i & 1) == 1) {
                msg += (char) 0;
            } else {
                msg += (char) pwd.charAt(0);
            }
        final_ = str_md5(msg);
        /*
         * Ensuite une partie pour ralenir les choses ! En JavaScript ça va être
         * vraiment lent !
         */
        String msg2;
        for (int i = 0; i < 1000; i++) {
            msg2 = "";
            if ((i & 1) == 1)
                msg2 += pwd;
            else
                msg2 += final_.substring(0, 16);
            if (i % 3 != 0)
                msg2 += salt;
            if (i % 7 != 0)
                msg2 += pwd;
            if ((i & 1) == 1) {
                msg2 += final_.substring(0, 16);
            } else {
                msg2 += pwd;
            }
            final_ = str_md5(msg2);
        }
        int[] _final = stringToArray(final_);

        /*
         * Now make the output string.
         */
        cpw = AP_MD5PW_ID + salt + '$';
        cpw += ap_to64((_final[0] << 16) | (_final[6] << 8) | _final[12], 4);
        cpw += ap_to64((_final[1] << 16) | (_final[7] << 8) | _final[13], 4);
        cpw += ap_to64((_final[2] << 16) | (_final[8] << 8) | _final[14], 4);
        cpw += ap_to64((_final[3] << 16) | (_final[9] << 8) | _final[15], 4);
        cpw += ap_to64((_final[4] << 16) | (_final[10] << 8) | _final[5], 4);
        cpw += ap_to64(_final[11], 2);

        if (username.length() + 1 + cpw.length() > 255)
            return null;
        result = cpw;
        return result;
    }

    public static String getSalt(String oringinPass){
        if(oringinPass !=null && !"".equals(oringinPass)){
            String[] salt = oringinPass.split("\\$");
            if(salt.length > 1){
                return salt[2];
            }
        }
        return "";
    }
}
