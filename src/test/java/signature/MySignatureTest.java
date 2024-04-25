// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

package signature;

import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;

import signature.MySignature;

import java.util.*;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.io.IOException;

import java.security.*;
import javax.crypto.*;

public class MySignatureTest {
	/*
	 * if (isWindows)
	 * {
	 * builder.command("cmd.exe", "/c", "dir");
	 * }
	 * else
	 * {
	 * builder.command("sh", "-c", "ls");
	 * }
	 */

	// ProcessBuilder talvez???
	// System.out.println( "Iniciando verificação da assinatura" );
	// System.out.println( "verificação da assinatura terminada" ); */
	// System.out.println( "Iniciando criptografia da mensagem" );
	// System.out.println( "criptografia da mensagem terminada" );
	// System.out.println( "Iniciando criptografia do digest" );
	// System.out.println( "criptografia do digest terminado" );
	// System.out.println("Digest:\n "+
	// HexCodeString(MySignature.HexCodeString(digest)));
	// System.out.println("Assinatura:\n "+
	// HexCodeString(MySignature.HexCodeString(assinatura)));

	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("Usage: java MySignatureTest signatureStandard text");
			System.exit(1);
		}

		String algorithm = args[0];
		String message = args[1];

		try {
			// Gerar par de chaves assimétricas
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm.contains("RSA") ? "RSA" : "EC");
			KeyPair keyPair = keyGen.generateKeyPair();

			// Inicializar MySignature
			MySignature mySignature = MySignature.getInstance(algorithm);

			// Inicializar para assinatura
			mySignature.initSign(keyPair.getPrivate());

			// Atualizar com a mensagem
			mySignature.update(message/* .getBytes()*/);

			// Assinar a mensagem
			byte[] signature = mySignature.sign();

			// Inicializar para verificação
			mySignature.initVerify(keyPair.getPublic());

			// Atualizar com a mesma mensagem
			mySignature.update(message/*.getBytes()*/);

			// Verificar a assinatura
			boolean verified = mySignature.verify(signature);

			// Imprimir resultados
			System.out.println("Algorithm: " + algorithm);
			System.out.println("Message: " + message);
			System.out.println("Signature: " + bytesToHex(signature));
			System.out.println("Signature verified: " + verified);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
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