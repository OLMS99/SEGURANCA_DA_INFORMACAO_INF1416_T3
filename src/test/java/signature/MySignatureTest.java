// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

package signature;

import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;

//import signature.MySignature;

import java.util.*;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.io.IOException;

import java.security.*;
import javax.crypto.*;

public class MySignatureTest {
	private static String SO = System.getProperty("os.name").toLowerCase();
	public static boolean IS_WINDOWS = SO.indexOf("win") >= 0;
	public static boolean IS_UNIX = SO.indexOf("nix") >= 0 || SO.indexOf("nux") >= 0 || SO.indexOf("aix") > 0;

	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("Usage: java MySignatureTest signatureStandard text");
			System.exit(1);
		}

		String algorithm = args[0];
		String message = args[1];

		try {
			// Gera par de chaves assimétricas
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); // SHA256withECDSA retirado
			KeyPair keyPair = keyGen.generateKeyPair();

			MySignature mySignature = MySignature.getInstance(algorithm);

			mySignature.initSign(keyPair.getPrivate());

			mySignature.update(message);

			byte[] signature = mySignature.sign();

			mySignature.initVerify(keyPair.getPublic());

			mySignature.update(message);

			boolean verified = mySignature.verify(signature);

			System.out.println("Algorithm: " + algorithm);
			System.out.println("Message: " + message);
			System.out.println("Signature: " + bytesToHex(signature));
			System.out.println("Signature verified: " + verified);

		} catch (Exception e) {
			e.printStackTrace();
		}
		/* 
		try{
		Process processoTeste;
		if (IS_WINDOWS){
			processoTeste = new ProcessBuilder("java MySignature").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA1withRSA").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature MD5withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA1withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA256withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA512withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
		}
		else if (IS_UNIX){
			processoTeste = new ProcessBuilder("java MySignature").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA1withRSA").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature MD5withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA1withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA256withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
			processoTeste = new ProcessBuilder("java MySignature SHA512withRSA 'MENSAGEM SECRETA'").start();
			System.out.println(processoTeste.getOutputStream());
		}
		else{
			System.out.println("Sistema operacional não suportado para o teste");
		}
		} catch(IOException e){
			System.err.println("erro ao tentar testar comandos da classe MySignature");
			System.exit(1);
		}
		*/
	}

	private static String bytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02X", b));
		}
		return result.toString();
	}

	// receber o padrão de assinatura e a string que deve ser assinada, nesta ordem,
	// como argumento na linha de comando

	// gerar o par de chaves assimétricas para gerar a assinatura digital da string
	// recebida na linha de comando

	// instanciar e usar os metodos da classe MySignature para gerar e verificar a
	// assinatura digital da string recebida na linha de comando

	// imprimir, na saída padrão, todos os passos executados para gerar a assinatura
	// digital da string no padrão solicitado

	// imprimir, na saída padrão, o resumo de mensagem (digest) e a assinatura
	// digital no formato hexadecimal
}