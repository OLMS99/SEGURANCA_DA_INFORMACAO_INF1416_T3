// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

import java.util.*;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.security.*;
import javax.crypto.*;

public class MySignature
{
	private String cypherDigest;
	private String cypherSignature;
	private MessageDigest digestTipo;
	private KeyPairGenerator keyGen;
	
	public static void main(String[] args)
	{
		String signatureStandard = args[0];
		String plainText = args[1];

		if (args.length !=2)
		{
			System.err.println("Usage: java DigitalSignatureExample signatureStandard text");
			System.exit(1);
		}
		
		MySignature signningProcess = MySignature.getInstance(signatureStandard);
		
		System.out.println( "Iniciando criptografia da mensagem" );
		byte[] digest =  signningProcess.makeDigest(plainText);
		System.out.println( "criptografia da mensagem terminado" );

		System.out.println( "Iniciando criptografia do digest" );
		KeyPair chaves = signningProcess.keyGen.generateKeyPair();
		// signningProcess.initSign(chaves.getPrivate());
		// signningProcess.update(digest);
		// byte[] assinatura = signningProcess.sign();
		// System.out.println( "criptografia do digest terminado" );

		// System.out.println( "Iniciando verificação da assinatura" );
		// signningProcess.initVerify(chaves.getPublic())
		// signningProcess.update(digest)

		/*try
		{
			if (signningProcess.verify(assinatura)) 
			{
				System.out.println( "Signature verified" );
			} 
		  	else
			{ 
				System.out.println( "Signature failed" );
			}
		} 
		catch (SignatureException se) 
		{
			System.out.println( "Singature failed" );
		}

		System.out.println( "verificação da assinatura terminada" ); */

		// System.out.println("Digest:\n "+ HexCodeString(MySignature.HexCodeString(digest)));
		// System.out.println("Assinatura:\n "+ HexCodeString(MySignature.HexCodeString(assinatura)));
	}
	
	private static class SingletonHelper
	{
		private static final MySignature MD5withRSA = new MySignature("MD5","RSA");
		private static final MySignature SHA1withRSA = new MySignature("SHA1","RSA");
		private static final MySignature SHA256ithRSA = new MySignature("SHA256","RSA");
		private static final MySignature SHA512withRSA = new MySignature("SHA512","RSA");
		private static final MySignature SHA256withECDSA = new MySignature("SHA256","EdDSA");
	}

	private MySignature(String tipoDigest, String geChave)
	{
		if (tipoDigest.equals("SHA1") || tipoDigest.equals("SHA256") || tipoDigest.equals("SHA512"))
		{
			this.cypherDigest = tipoDigest.substring(0, 3) + "-" + tipoDigest.substring(3);
		} 
			
		else
		{
			this.cypherDigest = tipoDigest;
		}

		this.cypherSignature = geChave;
		
		try
		{
			this.keyGen = KeyPairGenerator.getInstance(geChave);
		}
		catch(NoSuchAlgorithmException e)
		{
			System.err.println(geChave+" não é um algoritmo suportado");
			System.exit(1);
		}
		
		try{
			this.digestTipo = MessageDigest.getInstance(this.cypherDigest);
		}
		catch(NoSuchAlgorithmException e){
			System.err.println(this.cypherDigest+" não é um algoritmo suportado");
			System.exit(1);
		}
		
	}
	
	public static MySignature getInstance(String padraoAssinatura)
	{
		// Padrões de assinatura suportados:
		HashSet<String> padroesSuportadosAss = new HashSet<String>(Arrays.asList("MD5withRSA", "SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "SHA256withECDSA"));

		if(!padroesSuportadosAss.contains(padraoAssinatura))
		{
			System.err.println("Padrão de assinatura não suportado");
			System.exit(1);
		}

		switch(padraoAssinatura)
		{
			case "MD5withRSA":
				return SingletonHelper.MD5withRSA;
			case "SHA1withRSA":
				return SingletonHelper.SHA1withRSA;
			case "SHA256withRSA":
				return SingletonHelper.SHA256ithRSA;
			case "SHA512withRSA":
				return SingletonHelper.SHA512withRSA;
			case "SHA256withECDSA":
				return SingletonHelper.SHA256withECDSA;
			default:
				System.err.println("Padrão de assinatura não suportado");
				return null;
		}
	}
	
	protected byte[] makeDigest(String text) 
	{
		// adequado: Update(Byte[], Int32, Int32)
		int bufferSize = 1024;
		byte[] result = {};

		try 
		{
			byte[] bytebuffer = new byte[bufferSize];
			InputStream leitor = new ByteArrayInputStream(text.getBytes());
			int check = leitor.read(bytebuffer);

			while (check != -1)
			{
				digestTipo.update(bytebuffer, 0, check);
				check = leitor.read(bytebuffer);
			}

			leitor.close();
			result = digestTipo.digest();

		} 
		catch (IOException e)
		{

			System.err.println("Erro na leitura do arquivo durante o calculo do digest");
			System.exit(1);

		}
		 
		return result;
	}

	// protected  initSign(privateKey chavePrivada){}
	// protected  update(String text){}
	// protected  byte[] sign(){}
	// protected  initVerify(publicKey chavePublica){}
	// protected  verify(byte[] signature){}
	// use to make the signature: Cipher +
	// AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(DigestTipo);
	// DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, messageHash);
	// byte[] hashToEncrypt = digestInfo.getEncoded();
	// sign() returns signature
	// initVerify(keypair.getPublic())
	// verify(signature)

	private static String HexCodeString(byte[] hexCode)
	{
		StringBuffer buf = new StringBuffer();

		for (int i = 0; i < hexCode.length; i++)
		{
			String hex = Integer.toHexString(0x0100 + (hexCode[i] & 0x00FF)).substring(1);
			buf.append((hex.length() < 2 ? "0" : "") + hex);
		}

		return buf.toString();
	}
}