package com.getkwikid.enc;

import java.util.Base64;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import io.github.cdimascio.dotenv.Dotenv;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;


import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Calendar;

import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import java.io.StringReader;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

import org.json.JSONObject;
//import org.json.XML;
import org.json.JSONException;

import java.util.concurrent.ThreadLocalRandom;

import static spark.Spark.*;
import spark.Filter;
import static spark.Spark.get;
import static spark.Spark.after;
import spark.Request;
import spark.Response;
import spark.Route;

public class App {

	/*
	 * static { Security.addProvider(new BouncyCastleProvider()); }
	 */


	public String readPrivateKey() throws IOException {
		byte[] fileBytes = Files.readAllBytes(Paths.get("/home/ubuntu/icici/enc/private_key.ppk"));
		String fileContent = new String(fileBytes);
		System.out.println(fileContent);
		return fileContent.replace("\n", "").replace("\r", "");
	}

	public String readEncryptedData() throws IOException {
                byte[] fileBytes = Files.readAllBytes(Paths.get("/home/ubuntu/icici/enc/encrypted_data.txt"));
                String fileContent = new String(fileBytes);
		//System.out.println(fileContent);
                return fileContent.replace("\n", "").replace("\r", "");
        }

	public byte[] asymmetricencrypt(byte[] skey, byte[] publicKey) throws GeneralSecurityException {
		String encryptionAlgo="RSA/ECB/PKCS1Padding";
		PublicKey x509Key = getPublic(publicKey,"RSA");
		Cipher cipher = Cipher.getInstance(encryptionAlgo);
		cipher.init(1, x509Key);
		return cipher.doFinal(skey);
	}

	public PrivateKey getPrivate(byte[] privateKey, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException {
		System.out.println("getting private key");
		byte[] decodedpvkey = Base64.getDecoder().decode(privateKey);
		System.out.println("decoding private key");
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedpvkey);
		System.out.println("ekspec private key");
		KeyFactory kf = KeyFactory.getInstance(mode);
		System.out.println("got keyfactory");

		return kf.generatePrivate(spec);
	}

	public PublicKey getPublic(byte[] publicKey, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
		KeyFactory kf = KeyFactory.getInstance(mode);
		return kf.generatePublic(spec);
	}

	public byte[] symmetricencrypt(byte[] content, byte[] iv, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		String encryptionAlgo="AES/CBC/PKCS5Padding";
		SecretKeySpec secretKey = getSecretKey(key,"AES");
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance(encryptionAlgo);
		cipher.init(1,secretKey,ivParams);
		return cipher.doFinal(content);
	}

	public byte[] asymmetricdecrypt(byte[] encryptedkey, byte[] privateKey) throws GeneralSecurityException {
		System.out.println("asymmetricdecrypt called");
		PrivateKey pkcs8PrivateKey = getPrivate(privateKey, "RSA");
		System.out.println("key loaded");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		System.out.println("got cipher instance");
	    cipher.init(2, pkcs8PrivateKey);
	    System.out.println("done with cipher init");
	    return cipher.doFinal(encryptedkey);
	}

	public byte[] symmetricdecrypt(byte[] encryptedContent, byte[] iv, byte[] key) throws GeneralSecurityException {
	      SecretKeySpec secretKey =getSecretKey(key,"AES");
	      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	      IvParameterSpec ivParams = new IvParameterSpec(iv);
	      cipher.init(2, secretKey, ivParams);
	      return cipher.doFinal(encryptedContent);
	   }

	public SecretKeySpec getSecretKey(byte[] keyBytes, String algorithm) {
		return new SecretKeySpec(keyBytes, algorithm);
	}
	public SecretKeySpec generateSecretKey(int length, String algorithm) {
		SecureRandom rnd = new SecureRandom();
		byte[] key = new byte[length];
		rnd.nextBytes(key);
		SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
		return secretKey;
	}

	public byte[] generateIv(String cipherAlgorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);
		SecureRandom random = SecureRandom.getInstanceStrong();
		byte[] iv = new byte[cipher.getBlockSize()];
		random.nextBytes(iv);
		return iv;
	}

	public String randomString(int len) {
		StringBuilder sb = new StringBuilder(len);
		SecureRandom rnd = new SecureRandom();
		for(int i = 0; i < len; ++i) {
			sb.append("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(rnd.nextInt("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".length())));
		}

		return sb.toString();
	}

	public byte[] mergeTwoByteArrays(byte[] arrayOne, byte[] arrayTwo) {
		byte[] mergedArray = new byte[arrayOne.length + arrayTwo.length];
		System.arraycopy(arrayOne, 0, mergedArray, 0, arrayOne.length);
		System.arraycopy(arrayTwo, 0, mergedArray, arrayOne.length, arrayTwo.length);
		return mergedArray;
	}

	 public byte[] extractBytes(byte[] input, int startIndex, int endIndex) {
	      return Arrays.copyOfRange(input, startIndex, endIndex);
	   }
	 
	public static void main(String[] args) {

		App enc=new App();
		port(4366);
		Dotenv dotenv = Dotenv.load();
		//byte[] EncryptedKey;
		//byte[] encodedEncryptedKey=null;
		//byte[] EncryptedData;
		//byte[] encodedEncryptedData=null;



		
	//final String publicKey="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsIwVStQi6aSMLBZu3vhafOR5NTMNp+TXPwyk/6VoaSQfDnZaSQPYhdt4a8X215KwXwpIL1eBJOH2NW8jp5AO4WauHWEwEggJvPaC8FgzZtDhjYexOk+/yaDbY7U9BofJSU76VIBxRoN7YmAknAKrpfn0ukXPPuUx5Ny/cy85nunqo5M8Acf2VVwSGZQMBZFSm3yxYOdS4laDlM+s1w+5wLDMjYSgIMm76rpVdO3hs2n2dSAYM6XMOaqNDwHdZk6n8lPgivYVXjTz7KU9eqkFnecWvn2ugRI7hgrplZxS020k0QBeYd0AH7zJZKS3Xo5VycL01UO/WYOQvB7v8lge7TiQZ3CCrnuykqcJ/r5DMLO/cKQAeZi+LQ95FQg39joO8G7bfO7+a3Gs8Re3mRW7AA8x1aEn7XZMOUu4l4IfNvwh20V4cz3xvGXdr9ZLFvgX5593MxCDBjkiaynzG8gmLVTIoaItPy+khwO/vjfWka0L3yvT3l55R4H/KRKxlHaY58HVdLbuWrUoH/4gbkYFYFC+rejBW5wbE0FJmWIkEXLKsTlXcsn6eAzi4BRxidQ/4rIEf8qWpSFzJobivBnWe4bpBA19g3N47PDpD5xS6uj7ODSBhEn22UnsiDaGV+RhsXYA/xqaJCjB6+W7CN00Lowr87sUoT4VAK8wrOk4D5sCAwEAAQ==";  // Public Key 
		//String privateKey="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";
		//try{
	//		privateKey=enc.readPrivateKey();
	//	}catch(Exception  e){
	//		e.printStackTrace();
	//		privateKey="";
	//	}
		post("/decrypt", (request, response) -> {
			try{
			//String privateKey="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";
			//String privateKey="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";

			String domain = "UAT";
			String privateKey = dotenv.get(domain+"_PRT_KEY");

			String bodytodecrypt = new String(request.body());
			//String encodedEncryptedKeyRes = "";
			//String encodedEncryptedDataRes = "";
			App decdo=new App();
			JSONObject nJSONObj = new JSONObject(bodytodecrypt);
			String encodedEncryptedKeyRes = nJSONObj.get("encryptedKey").toString();
			String encodedEncryptedDataRes = nJSONObj.get("encryptedData").toString();
			//nJSONObj.put("decryptedData","wohoo");
			//nJSONObj.put("datatodecrypt",bodytodecrypt);
		    	response.type("application/json");
                    //response.body(nJSONObj.toString());
                    //return nJSONObj.toString();
			//String contentToDecrypt = nJSONObj.get("bodyToDecrypt")
		   	                        // Decryption 
                        System.out.println(encodedEncryptedDataRes);
                        byte [] decryptedKey = null;
                        byte [] decodedKey=null;
                        byte [] decodedContent=null;
                        byte [] decryptedContent=null;
                        byte [] decodedIv=null;
                        decodedKey=Base64.getDecoder().decode(encodedEncryptedKeyRes);
                        System.out.println("key decoded");
                        decodedContent = Base64.getDecoder().decode(encodedEncryptedDataRes);
                        System.out.println("content decoded");
                        decodedIv = decdo.extractBytes(decodedContent, 0, 16);
                        System.out.println("retrieved IV");
                        decodedContent = decdo.extractBytes(decodedContent, 16, decodedContent.length);
                        System.out.println("retrieved decodedcontent");
                        decryptedKey = decdo.asymmetricdecrypt(decodedKey, privateKey.getBytes());
                        System.out.println("decryptedKey : "+new String(decryptedKey));
                        decryptedContent=decdo.symmetricdecrypt(decodedContent, decodedIv, decryptedKey);
                        System.out.println("decryptedContent : "+new String(decryptedContent));
			JSONObject resjson = new JSONObject();
			resjson.put("decryptedData",new String(decryptedContent));
			response.body(resjson.toString());
			return resjson.toString();
		   }catch(Exception e){
			System.out.println("Exception while decrypting");
			System.out.println(e);
			e.printStackTrace();
		   	return "not ok";
		   }

		});
		
		post("/encrypt", (request, response) -> {
   			 // Create something
			 //String publicKey="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsIwVStQi6aSMLBZu3vhafOR5NTMNp+TXPwyk/6VoaSQfDnZaSQPYhdt4a8X215KwXwpIL1eBJOH2NW8jp5AO4WauHWEwEggJvPaC8FgzZtDhjYexOk+/yaDbY7U9BofJSU76VIBxRoN7YmAknAKrpfn0ukXPPuUx5Ny/cy85nunqo5M8Acf2VVwSGZQMBZFSm3yxYOdS4laDlM+s1w+5wLDMjYSgIMm76rpVdO3hs2n2dSAYM6XMOaqNDwHdZk6n8lPgivYVXjTz7KU9eqkFnecWvn2ugRI7hgrplZxS020k0QBeYd0AH7zJZKS3Xo5VycL01UO/WYOQvB7v8lge7TiQZ3CCrnuykqcJ/r5DMLO/cKQAeZi+LQ95FQg39joO8G7bfO7+a3Gs8Re3mRW7AA8x1aEn7XZMOUu4l4IfNvwh20V4cz3xvGXdr9ZLFvgX5593MxCDBjkiaynzG8gmLVTIoaItPy+khwO/vjfWka0L3yvT3l55R4H/KRKxlHaY58HVdLbuWrUoH/4gbkYFYFC+rejBW5wbE0FJmWIkEXLKsTlXcsn6eAzi4BRxidQ/4rIEf8qWpSFzJobivBnWe4bpBA19g3N47PDpD5xS6uj7ODSBhEn22UnsiDaGV+RhsXYA/xqaJCjB6+W7CN00Lowr87sUoT4VAK8wrOk4D5sCAwEAAQ==";  // Public Key 

				//String publicKey="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqcsOb7b8zjUwcCAfPaCOrTZjjZbmJWnPyBrDiCYM/zR1G7zjU0GrExHBTQEC4BpJY1d2TaNpXfGJep44wKndURXzS23DQ6uQM1kahxLyH23XJ2v8EQs9SlFUvhsmY46AwaL6AGRTaP4zOllOg2wOIg1uymkpE4HM7ev9LzaOfwaYg5bhTS1FB7ZTOg+JfWRcPwPcaBO45rObGkwqGDM/91YKa+pZqYO4HJHx5hxH3nEsE9Det/fsBhABnX8cwK98hHOsghPV4wSEYkxWnwSTt9knjui0LI5fGBmu5mLEDWI/l7dvpM7cquPzOfyORJ961lSoT+rOKO2wddLmTztgxxKOPTh5wq9jFatJcHKN+NcRij2lcGfaCH2V+iYe3GtMt4U1wAWawObF35mMGsWMc/+KNSWHomI6kr2HCpzbe3O6XKWCyogQv+kRDcVYKDap2ECWY/5mJHJrzTxZh75wBrZp0QPoZtOsHtHTFDtGUCYUqj+rHzOaA3majACMtvdWFlux6aIprYvHWxg/qTBUMY80uXLsT5fyYx3z0S1MfzEn9ul7tYYYH4eP/ZbHrjQI7h36kEvyok+gZ6bqqDKV5MfStBT3H63fE3R4bhhoobshLRH4/txtrjEmBOMRJg8eQUAk1wOseSOiEMjVDfiKK5Gw0ziXwdrY8YW0M64CEx0CAwEAAQ==";
			 	//String publicKey="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsIwVStQi6aSMLBZu3vhafOR5NTMNp+TXPwyk/6VoaSQfDnZaSQPYhdt4a8X215KwXwpIL1eBJOH2NW8jp5AO4WauHWEwEggJvPaC8FgzZtDhjYexOk+/yaDbY7U9BofJSU76VIBxRoN7YmAknAKrpfn0ukXPPuUx5Ny/cy85nunqo5M8Acf2VVwSGZQMBZFSm3yxYOdS4laDlM+s1w+5wLDMjYSgIMm76rpVdO3hs2n2dSAYM6XMOaqNDwHdZk6n8lPgivYVXjTz7KU9eqkFnecWvn2ugRI7hgrplZxS020k0QBeYd0AH7zJZKS3Xo5VycL01UO/WYOQvB7v8lge7TiQZ3CCrnuykqcJ/r5DMLO/cKQAeZi+LQ95FQg39joO8G7bfO7+a3Gs8Re3mRW7AA8x1aEn7XZMOUu4l4IfNvwh20V4cz3xvGXdr9ZLFvgX5593MxCDBjkiaynzG8gmLVTIoaItPy+khwO/vjfWka0L3yvT3l55R4H/KRKxlHaY58HVdLbuWrUoH/4gbkYFYFC+rejBW5wbE0FJmWIkEXLKsTlXcsn6eAzi4BRxidQ/4rIEf8qWpSFzJobivBnWe4bpBA19g3N47PDpD5xS6uj7ODSBhEn22UnsiDaGV+RhsXYA/xqaJCjB6+W7CN00Lowr87sUoT4VAK8wrOk4D5sCAwEAAQ==";

				String domain = "UAT";
				String publicKey = dotenv.get(domain + "_PUB_KEY");
				System.out.println(request.attributes());
				System.out.println(request.body());
			 	//String bodyToEncrypt = request.attribute("contentToEncrypt");
			 	//return "okn";
				String bodyToEncrypt = request.body();

			try {
				App encdo=new App();
				byte[] EncryptedKey;
				byte[] EncryptedData;
				byte[] plaintextKey = enc.generateSecretKey(16, "AES").getEncoded();
				byte[] iv = enc.generateIv("AES");
				byte[] encodedEncryptedKey=null;
				byte[] encodedEncryptedData=null;

				EncryptedKey = encdo.asymmetricencrypt(plaintextKey, publicKey.getBytes());
				encodedEncryptedKey = Base64.getEncoder().encode(EncryptedKey);

				EncryptedData=encdo.symmetricencrypt(bodyToEncrypt.getBytes(), iv, plaintextKey);
				encodedEncryptedData= Base64.getEncoder().encode(enc.mergeTwoByteArrays(iv, EncryptedData));

				System.out.println("raw data to encrypt:"+bodyToEncrypt);
				System.out.println("Encrypted Key :"+new String(encodedEncryptedKey));
				System.out.println("Encrypted Content :"+new String(encodedEncryptedData));

				JSONObject nJSONObj = new JSONObject();
				nJSONObj.put("encryptedkey",new String(encodedEncryptedKey));
				nJSONObj.put("encryptedcontent",new String(encodedEncryptedData));
				response.type("application/json");
				response.body(nJSONObj.toString());
				return nJSONObj.toString();
			} catch (GeneralSecurityException e){
				e.printStackTrace();
				return "Something went wrong";
			}
		});


post("/canaraencrypt", (request, response) -> {
                         // Create something
                         //String publicKey="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsIwVStQi6aSMLBZu3vhafOR5NTMNp+TXPwyk/6VoaSQfDnZaSQPYhdt4a8X215KwXwpIL1eBJOH2NW8jp5AO4WauHWEwEggJvPaC8FgzZtDhjYexOk+/yaDbY7U9BofJSU76VIBxRoN7YmAknAKrpfn0ukXPPuUx5Ny/cy85nunqo5M8Acf2VVwSGZQMBZFSm3yxYOdS4laDlM+s1w+5wLDMjYSgIMm76rpVdO3hs2n2dSAYM6XMOaqNDwHdZk6n8lPgivYVXjTz7KU9eqkFnecWvn2ugRI7hgrplZxS020k0QBeYd0AH7zJZKS3Xo5VycL01UO/WYOQvB7v8lge7TiQZ3CCrnuykqcJ/r5DMLO/cKQAeZi+LQ95FQg39joO8G7bfO7+a3Gs8Re3mRW7AA8x1aEn7XZMOUu4l4IfNvwh20V4cz3xvGXdr9ZLFvgX5593MxCDBjkiaynzG8gmLVTIoaItPy+khwO/vjfWka0L3yvT3l55R4H/KRKxlHaY58HVdLbuWrUoH/4gbkYFYFC+rejBW5wbE0FJmWIkEXLKsTlXcsn6eAzi4BRxidQ/4rIEf8qWpSFzJobivBnWe4bpBA19g3N47PDpD5xS6uj7ODSBhEn22UnsiDaGV+RhsXYA/xqaJCjB6+W7CN00Lowr87sUoT4VAK8wrOk4D5sCAwEAAQ==";  // Public Key 
				String publicKeyS="MIIHDDCCBfSgAwIBAgIMQQGuYTKtiqVPHUSgMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTgwNgYDVQQDEy9HbG9iYWxTaWduIEV4dGVuZGVkIFZhbGlkYXRpb24gQ0EgLSBTSEEyNTYgLSBHMzAeFw0yMzEwMDQwNDExMDNaFw0yNDExMDQwNDExMDJaMIG/MRowGAYDVQQPDBFHb3Zlcm5tZW50IEVudGl0eTEcMBoGA1UEBRMTR292ZXJubWVudCBFbnRpdGllczETMBEGCysGAQQBgjc8AgEDEwJJTjELMAkGA1UEBhMCSU4xEjAQBgNVBAgTCUthcm5hdGFrYTESMBAGA1UEBxMJQmVuZ2FsdXJ1MRQwEgYDVQQKEwtDYW5hcmEgQmFuazEjMCEGA1UEAxMadWF0dmlkZW9reWMuY2FuYXJhYmFuay5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNNSJ0B9nFHP2+xFGI7/gk5qt55QWTQbE87J6j7FHNmW5GyzzI7vsCCHZSSLlw1UT8kfhdUT6W8ngi+xGvtqe05VPq/5nsUwJVlYQCjTIvp0ompJJJ1k8iDcRbAlwscKg5iJPlKnEgVGePD7O6GDsQQlJIIrYyriBCh3NR56d99l+FkK0WXCbcRDuCptWf/RaDXsrxynFU826lgsJL6q0cFa5cYtf9f4OH8q9oZR5Jt24vbjDlU8qF3c6kJ5oGbVXx2zC/3cPRQYS9OgE9ame4baogzilCzBD6HwwX0C9TbxxS+XKYvK4mTVsJOFE26h8EOE+fvDAGgVK3iTzNm441AgMBAAGjggNiMIIDXjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADCBlgYIKwYBBQUHAQEEgYkwgYYwRwYIKwYBBQUHMAKGO2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZXh0ZW5kdmFsc2hhMmczcjMuY3J0MDsGCCsGAQUFBzABhi9odHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vZ3NleHRlbmR2YWxzaGEyZzNyMzBVBgNVHSAETjBMMEEGCSsGAQQBoDIBATA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBATBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzL2dzZXh0ZW5kdmFsc2hhMmczcjMuY3JsMCUGA1UdEQQeMByCGnVhdHZpZGVva3ljLmNhbmFyYWJhbmsuY29tMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBTds+dtqC7oxU5uz3TmdTyUFc7oHTAdBgNVHQ4EFgQU3RgNRVKzCmzGjwzsFGzBWbJ85lIwggF/BgorBgEEAdZ5AgQCBIIBbwSCAWsBaQB2AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABivjh2yYAAAQDAEcwRQIhALyq9S62L16mhnhT9PggZGiux4lk+rkx7maVEUhnufm2AiBbW10gVo5KWUpd8JCFxuds54TN/9NIb/+OVCfzmY1MhgB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABivjh2AgAAAQDAEcwRQIgeqzk9VyTC0B4kRpXtUOH4WGn75UetuocssIvbX8oAxECIQCvV93J9m2DY1fvrfyPXGCQHhOElWKibvkZ7+sMBG1VZAB3ANq2v2s/tbYin5vCu1xr6HCRcWy7UYSFNL2kPTBI1/urAAABivjh2CUAAAQDAEgwRgIhAOjvZmuVVzhwaq1fABH+8QEUUZE1rYaCXdMIBJe/zgaIAiEAtabZ2lCzP41fhOEXdGoTAlDKcnOGpKheIPC1KqVNFnQwDQYJKoZIhvcNAQELBQADggEBAEvimPPiqzhxx5Te5Ux+eRVxZ6KrI6JKLcHMdUaqbIpmcYRtCC+Wqqu2MxrksIl4tNkiMD6f3pnaqGoQPHECAYHLgUEPtCKU+eFUs3t2cyr52CBZ0/NaGoZV3dVjoyg/aDyoPLwaKebI2528V0ujhjkw5TUW/P2+ljHvt43AYSCSnICEkNFcUECWM+0TVz/MAFo4Osnx1fQUWuThMuCettiSkTWj22bHpq63icYS4VPHdsWfehhaCFNATcWLaur4n/lcz0Pw3XOsYr025qJexcAra1O3TpZ7k8sg2ZVn6/rmYGNzm+A4ag9+yxVUZiu/P+0RqYrf/OQylRqPN8V7EZE=";

                                System.out.println(request.attributes());
                                System.out.println(request.body());
                                //String bodyToEncrypt = request.attribute("contentToEncrypt");
                                //return "okn";
                                String bodyToEncrypt = request.body();

                        try {
                                App encdos=new App();
                                byte[] EncryptedKeys;
                                byte[] EncryptedDatas;
                                byte[] plaintextKeys = enc.generateSecretKey(16, "AES").getEncoded();
                                byte[] ivs = enc.generateIv("AES");
                                byte[] encodedEncryptedKeys=null;
				byte[] encodedEncryptedDatas=null;



                                EncryptedKeys = encdos.asymmetricencrypt(plaintextKeys, publicKeyS.getBytes());
                                encodedEncryptedKeys = Base64.getEncoder().encode(EncryptedKeys);


                                EncryptedDatas=encdos.symmetricencrypt(bodyToEncrypt.getBytes(), ivs, plaintextKeys);
                                encodedEncryptedDatas= Base64.getEncoder().encode(encdos.mergeTwoByteArrays(ivs, EncryptedDatas));

                                System.out.println("raw data to encrypt:"+bodyToEncrypt);
                                System.out.println("Encrypted Key :"+new String(encodedEncryptedKeys));
                                System.out.println("Encrypted Content :"+new String(encodedEncryptedDatas));

                                JSONObject nJSONObj = new JSONObject();
                                nJSONObj.put("encryptedkey",new String(encodedEncryptedKeys));
                                nJSONObj.put("encryptedcontent",new String(encodedEncryptedDatas));
                                response.type("application/json");
                                response.body(nJSONObj.toString());
                                return nJSONObj.toString();
                        } catch (GeneralSecurityException e){
                                e.printStackTrace();
				//return new String(e);
                                return "Something went wrong";
                        }
                });

		/*try{
			String encodedEncryptedKeyRes = "jCj+YRBPRw/MWrdRsfXoVkEpx08o4pb6Tev4M2RXh32pYtzplmOBJDrPGg6nwu+CYdD3g7Qfm9o7yK9G4oUhoN5t1g/AZ6Pm2/j1i8yQqkNDMWaOMtmhtf0AE8Mc9eIuds6fh4PW6umeK492tz5Kje64NB/nZOE2hj8+hMXIMo8TFeXMNa8cVUpIWPp9sLWBmfOgwc16tYOn/V93IkjsXoDO9s4VgC/irCk9bDz+a2Y0owreMR0BzpeylcUW9SsnsJGaVyDRD1RD0c18IdOr6FNh3PPULtGu+/iHQz1MLo6M1uuDzbrz5m0Pw8mwpqBpeqZNlvF1d+psMe+pT1mMFAwt3Uz33IPhjQTSxTM13z8ylTgThVx4PF/Q4N27hKUUvZsNz3zz1y+cYrB2asgqhRsxR3FbEcz2wsP5Rg0T9EBd/B9f0EFc+IEUrb96BLRZLKWHUzKuM8WTyqpfZnnoTNH1F24pelEKZZ3/w03f43+zen9+U8ySEBfMOHRe9nQL6Y61WYkHZAzOtFWrAvCs94qMLaMwhuGl9mFL2XRw+Y/Vu6SIJR4JtKv67v2wZZT9Oo2kSRPhCKtrMhK+xpb+HjO7GmtQ4iQicHWv0164KVfL71tMjje4ulkMxz8kTs3G/pfnkihJG1e6/qOi/AGpaXaKB2v/FCxWwpGq3Oym7Tw=";
			String encodedEncryptedDataRes = "";
			try{			
				encodedEncryptedDataRes = enc.readEncryptedData().replace("\n", "").replace("\r", "");
			}catch(Exception e){
				e.printStackTrace();
				encodedEncryptedDataRes = "";
			}
			// Decryption 
			System.out.println(encodedEncryptedDataRes);
			byte [] decryptedKey = null;
			byte [] decodedKey=null;
			byte [] decodedContent=null;
			byte [] decryptedContent=null;
			byte [] decodedIv=null;
			decodedKey=Base64.getDecoder().decode(encodedEncryptedKeyRes);
			System.out.println("key decoded");
			decodedContent = Base64.getDecoder().decode(encodedEncryptedDataRes);
			System.out.println("content decoded");
			decodedIv = enc.extractBytes(decodedContent, 0, 16);
			System.out.println("retrieved IV");
			decodedContent = enc.extractBytes(decodedContent, 16, decodedContent.length);
			System.out.println("retrieved decodedcontent");
			decryptedKey = enc.asymmetricdecrypt(decodedKey, privateKey.getBytes());
			System.out.println("decryptedKey : "+new String(decryptedKey));
			decryptedContent=enc.symmetricdecrypt(decodedContent, decodedIv, decryptedKey);
			System.out.println("decryptedContent : "+new String(decryptedContent));




		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/

	}

}
