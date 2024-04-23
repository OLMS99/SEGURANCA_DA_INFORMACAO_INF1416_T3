// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

import java.util.*;

import java.security.*;
import javax.crypto.*;

public class MySignature
{
	private MessageDigest digestTipo;
	private KeyPairGenerator keyGen;
	
	public static void main(String[] args)
	{
		String signatureStandard = args[0];
		byte[] plainText = args[1];

		if (args.length !=2)
		{
			System.err.println("Usage: java DigitalSignatureExample signatureStandard text");
			System.exit(1);
		}
		
		MySignature signningProcess = MySignature.getInstance(signatureStandard);
		//System.out.println( "Iniciando criptografia da mensagem:" );
		// byte[] digest =  signningProcess.makeDigest(plainText)
		//
		//System.out.println( "criptografia da mensagem terminado" );

		//System.out.println( "Iniciando criptografia do digest" );
		//KeyPair chaves = signningProcess.keyGen.generateKeyPair()
		//signningProcess.initSign(chaves.getPrivate())
		//signningProcess.update(digest)
		//byte[] assinatura = signningProcess.sign();
		//
		//System.out.println( "criptografia do digest terminado" );

		//System.out.println( "Iniciando verificação da assinatura" );
		//signningProcess.initVerify(chaves.getPublic())
		//signningProcess.update(digest)
		//try {
		//	if (signningProcess.verify(assinatura)) {
		//		System.out.println( "Signature verified" );
		//	} else System.out.println( "Signature failed" );
		//} catch (SignatureException se) {
		//	System.out.println( "Singature failed" );
		//}
		//System.out.println( "verificação da assinatura terminada" );

		//System.out.println("Digest:\n "+ HexCodeString(MySignature.HexCodeString(digest)));
		//System.out.println("Assinatura:\n "+ HexCodeString(MySignature.HexCodeString(assinatura)));
	}
	
	private static class SingletonHelper
	{
		try
		{
			private static final MySignature MD5withRSA = new MySignature("MD5","RSA");
			private static final MySignature SHA1withRSA = new MySignature("SHA1","RSA");
			private static final MySignature SHA256ithRSA = new MySignature("SHA256","RSA");
			private static final MySignature SHA512withRSA = new MySignature("SHA512","RSA");
			private static final MySignature SHA256withECDSA = new MySignature("SHA256","ECDSA");
			
		} 
		catch (Exception e) 
		{
			System.err.println("Erro ao iniciar a classe MySignature");
			System.exit(1);
		}
	}

	private MySignature(String tipoDigest, String keyGen)
	{
		if (tipoDigest.equals("SHA1") || tipoDigest.equals("SHA256") || tipoDigest.equals("SHA512"))
		{
			this.digestTipo = MessageDigest.getInstance(tipoDigest.substring(0, 3) + "-" + tipoDigest.substring(3));
		} 
			
		else
		{
			this.digestTipo = MessageDigest.getInstance(tipoDigest);
		}

		this.keyGen = KeyPairGenerator.getInstance(keyGen);
	}
	
	public static MySignature getInstance(String padraoAssinatura)
	{
		// Padrões de assinatura suportados:
		HashSet<String> padroesSuportadosAss = new HashSet<String>(Arrays.asList("MD5withRSA", "SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "SHA256withECDSA"));

		if(!padroesSuportadosAss.contains(padraoAssinatura)){
			System.err.println("Padrão de assinatura não suportado");
			System.exit(1);
		}
		switch(padraoAssinatura){
			case "MD5withRSA":
				return SingletonHelper.MD5withRSA;
			case "SHA1withRSA":
				return SingletonHelper.SHA1withRSA;
			case "SHA256withRSA":
				return SingletonHelper.SHA256withRSA;
			case "SHA512withRSA":
				return SingletonHelper.SHA512withRSA;
			case "SHA256withECDSA":
				return SingletonHelper.SHA256withECDSA
		}
	}
	
	protected byte[] makeDigest(String text) {

		// adequado: Update(Byte[], Int32, Int32)
		int bufferSize = 1024;
		byte[] result = {};
		try {
			byte[] bytebuffer = new byte[bufferSize];
			InputStream leitor = new InputStream(text);
			int check = leitor.read(bytebuffer);
			while (check != -1) {
				digestTipo.update(bytebuffer, 0, check);
				check = leitor.read(bytebuffer);
			}

			leitor.close();
			result = digestTipo.digest();

		} catch (IOException e) {

			System.err.println("Erro na leitura do arquivo durante o calculo do digest");
			System.exit(1);

		} catch (NoSuchAlgorithmException e) {

			System.err.println("Error: Esse tipo de digest não é suportado por essa aplicação");
			System.exit(1);

		}
		return result;
	}

	// initSign(keypair.getPrivate())
	// update(text)
	// use to make the signature: Cipher +
	//AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(DigestTipo);
	//DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, messageHash);
	//byte[] hashToEncrypt = digestInfo.getEncoded();
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