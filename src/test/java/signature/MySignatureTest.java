// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

package signature;

import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;

public class MySignatureTest {
	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("Usage: java MySignatureTest signatureStandard text");
			System.exit(1);
		}

		String signatureStandard = args[0];
		String plainText = args[1];

		try {

			// Gera par de chaves assimétricas
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); // SHA256withECDSA retirado
			keyGen.initialize(4096);
			KeyPair keyPair = keyGen.generateKeyPair();

			MySignature mySignature = MySignature.getInstance(signatureStandard);

			mySignature.initSign(keyPair.getPrivate());
			mySignature.update(plainText);
			byte[] signature = mySignature.sign();

			mySignature.initVerify(keyPair.getPublic());
			mySignature.update(plainText);
			boolean verified = mySignature.verify(signature);

			System.out.println("Algorithm: " + signatureStandard);
			System.out.println("Message: " + plainText);
			System.out.println("Signature: " + bytesToHex(signature));
			System.out.println("Signature verified: " + verified);

		} catch (Exception e) {
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