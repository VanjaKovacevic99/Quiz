package cryptography;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class Cryptography {

    static final String algorithmName="AES/CBC/PKCS5Padding";
    static final String algorithmKey="AES";
    static final String sessionKey="sigurnost";
    static final String resultLocation="src" + File.separator + "result";
    static final String encryptionLocationResult= resultLocation + File.separator + "result.dec";
    static final String decryptionLocationResult= resultLocation + File.separator + "result.txt";

    public static String getEncryptionLocationResult(){
        return encryptionLocationResult;
    }
    public static String getDecryptionLocationResult(){
        return decryptionLocationResult;
    }

    public static String getAlgorithmName(){
        return algorithmName;
    }

    public static String getAlgorithmKey(){
        return algorithmKey;
    }

    public static String getSessionKey(){
        return sessionKey;
    }



    //ovo je za simetricne algoritme enkripcija
    public static byte[] encryptFileSymmetricAlgorithm(String locationFile, String destinationFileLocation, String sessionKey, String algorithmName, String algorithmKey, int ivLenght, int keySize) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] clean = Files.readAllBytes(Paths.get(locationFile));
        // Generating IV.
        byte[] iVector = new byte[ivLenght];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iVector);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iVector);

        // Hashing key.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(sessionKey.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = new byte[keySize];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithmKey);

        // Encrypt.
        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivLenght + encrypted.length];
        System.arraycopy(iVector, 0, encryptedIVAndText, 0, ivLenght);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivLenght, encrypted.length);

        OutputStream outputStream = new FileOutputStream(destinationFileLocation);
        outputStream.write(encryptedIVAndText);

        outputStream.close();
        return encryptedIVAndText;
    }

    public static byte[] decryptFileWithSymmetricAlgorithm(String fileLocationString, String destinationFileLocation, String sessionKey, String algorithmName, String algorithmKey, int initializationVectorSize, int keySize) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        byte[] encryptedIvTextBytes = Files.readAllBytes(Paths.get(fileLocationString));

        // Extract IV.
        byte[] initializationVector = new byte[initializationVectorSize];
        System.arraycopy(encryptedIvTextBytes, 0, initializationVector, 0, initializationVector.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - initializationVectorSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, initializationVectorSize, encryptedBytes, 0, encryptedSize);

        // Hash key.
        byte[] keyBytes = new byte[keySize];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sessionKey.trim().getBytes(StandardCharsets.UTF_8));
        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithmKey);

        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance(algorithmName);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        OutputStream outputStream = new FileOutputStream(destinationFileLocation);
        outputStream.write(decrypted);

        outputStream.close();
        return decrypted;
    }




    }





