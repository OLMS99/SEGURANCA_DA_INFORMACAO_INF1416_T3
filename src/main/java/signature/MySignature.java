// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

package signature;

import java.util.*;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.io.IOException;

import java.security.*;

import javax.crypto.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MySignature {
	private Boolean signning;
	private Boolean verifying;
	private ByteBuffer buffer;

	private final String cypherDigest;
	private final String cypherSignature;
	private MessageDigest digestTipo;

	private Cipher cifra;
	private Key holder;

	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("Usage: java MySignature signatureStandard text");
			System.exit(1);
		}

		try {
			if (Security.getProvider("BC") == null) {
				java.security.Security.addProvider(new BouncyCastleProvider());
			}
		} catch (Exception e) {
			System.err.println("Erro ao carregar o provider BouncyCastle");
			System.exit(1);
		}

		String signatureStandard = args[0];
		String plainText = args[1];

		MySignature signningProcess = MySignature.getInstance(signatureStandard);
		KeyPairGenerator keyGen = null;
		KeyPair chaves = null;
		try {
			keyGen = KeyPairGenerator.getInstance(signningProcess.cypherSignature);
			keyGen.initialize(4096);
			chaves = keyGen.generateKeyPair();
		} catch (Exception e) {
			System.err.println("erro na geração de chaves");
			System.exit(1);
		}

		signningProcess.initSign(chaves.getPrivate());
		signningProcess.update(plainText);
		byte[] assinatura = signningProcess.sign();

		signningProcess.initVerify(chaves.getPublic());
		signningProcess.update(plainText);
		boolean verificationResult = signningProcess.verify(assinatura);

		System.out.println("Assinatura da mensagem: " + MySignature.HexCodeString(assinatura));
		System.out.println("Verificação da assinatura: " + (verificationResult ? "sucesso" : "falha"));
	}

	private static class SingletonHelper {
		private static final MySignature MD5withRSA = new MySignature("MD5", "RSA");
		private static final MySignature SHA1withRSA = new MySignature("SHA1", "RSA");
		private static final MySignature SHA256ithRSA = new MySignature("SHA256", "RSA");
		private static final MySignature SHA512withRSA = new MySignature("SHA512", "RSA");
	}

	private MySignature(String tipoDigest, String tipoCifra) {
		this.signning = false;
		this.verifying = false;

		if (tipoDigest.equals("SHA1") || tipoDigest.equals("SHA256") || tipoDigest.equals("SHA512")) {
			this.cypherDigest = tipoDigest.substring(0, 3) + "-" + tipoDigest.substring(3);
		} else {
			this.cypherDigest = tipoDigest;
		}

		this.cypherSignature = tipoCifra;
		this.signning = false;
		this.verifying = false;
		try {
			this.cifra = Cipher.getInstance(tipoCifra);
		} catch (NoSuchAlgorithmException e) {
			System.err.println(tipoCifra + " não é um algoritmo suportado");
			System.exit(1);
		} catch (NoSuchPaddingException e) {
			System.err.println(tipoCifra + " não é um padding suportado");
			System.exit(1);
		}

		try {
			this.digestTipo = MessageDigest.getInstance(this.cypherDigest, "BC");
		} catch (NoSuchAlgorithmException e) {
			System.err.println(this.cypherDigest + " não é um algoritmo de digest suportado");
			System.exit(1);
		} catch (NoSuchProviderException e) {
			System.err.println("Provider BouncyCastle indisponível na coleta de instancia de calculo de digest");
			System.exit(1);
		}

		this.cifra = null;
		try {
			this.cifra = Cipher.getInstance(tipoCifra, "BC");
		} catch (NoSuchPaddingException e) {
			System.err.println(this.cypherDigest + " não é um padding suportado");
			System.exit(1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println(this.cypherDigest + " não é um algoritmo suportado");
			System.exit(1);
		} catch (NoSuchProviderException e) {
			System.err.println("Provider BouncyCastle indisponível na coleta de instancia de cifra");
			System.exit(1);
		}
	}

	public static final MySignature getInstance(String padraoAssinatura) {
		HashSet<String> padroesSuportadosAss = new HashSet<String>(
				Arrays.asList("MD5withRSA", "SHA1withRSA", "SHA256withRSA", "SHA512withRSA"));

		if (!padroesSuportadosAss.contains(padraoAssinatura)) {
			System.err.println("Padrão de assinatura não suportado");
			System.exit(1);
		}

		switch (padraoAssinatura) {
			case "MD5withRSA":
				return SingletonHelper.MD5withRSA;
			case "SHA1withRSA":
				return SingletonHelper.SHA1withRSA;
			case "SHA256withRSA":
				return SingletonHelper.SHA256ithRSA;
			case "SHA512withRSA":
				return SingletonHelper.SHA512withRSA;
			default:
				System.err.println("Padrão de assinatura não suportado");
				System.exit(1);
				return null;
		}
	}

	public byte[] makeDigest(byte[] text, int offset, int length) {
		// adequado: Update(Byte[], Int32, Int32)
		int bufferSize = 1024;
		byte[] result = {};
		System.out.println("Iniciando criptografia do digest");
		try {
			byte[] bytebuffer = new byte[bufferSize];
			InputStream leitor = new ByteArrayInputStream(text);
			int check = leitor.read(bytebuffer);

			while (check != -1) {
				digestTipo.update(bytebuffer, 0, check);
				check = leitor.read(bytebuffer);
			}

			leitor.close();
			result = digestTipo.digest();
		} catch (IOException e) {
			System.err.println("Erro na leitura da mensagem durante o calculo do digest");
			System.exit(1);
		}
		System.out.println("criptografia do digest terminado");
		System.out.println("Digest:\n" + HexCodeString(result) + "\n");
		return result;
	}

	public final void initSign(PrivateKey chavePrivada) {
		if (this.verifying) {
			System.err.println("Não é possível iniciar a assinatura enquanto verifica");
			System.exit(1);
		}
		if (this.signning) {
			System.err.println("Assinatura já está ativa");
			System.exit(1);
		}
		System.out.println("Iniciando assinatura da mensagem");
		this.signning = true;
		this.verifying = false;
		this.holder = chavePrivada;
		this.buffer = ByteBuffer.allocate(2048);
	}

	public final void update(String text) {
		byte[] plainText = text.getBytes();
		buffer.put(plainText);
	}

	public final byte[] sign() {
		byte[] digest = makeDigest(buffer.array(), 0, buffer.position());
		byte[] result = null;
		// criptografa com o cipher da instancia
		try {
			this.cifra.init(Cipher.ENCRYPT_MODE, holder);
			result = this.cifra.doFinal(digest);
		} catch (InvalidKeyException e) {
			System.err.println("Chave inválida na encriptação");
			System.exit(1);
		} catch (IllegalBlockSizeException e) {
			System.err.println("Erro no tamanho do bloco alocado na encriptação");
			System.exit(1);
		} catch (BadPaddingException e) {
			System.err.println("Erro no padding na encriptação");
			System.exit(1);
		}

		buffer.clear();
		this.signning = false;
		this.holder = null;
		System.out.println("criptografia da mensagem terminada");
		return result;
	}

	public final void initVerify(PublicKey chavePublica) {
		if (this.signning) {
			System.err.println("Não é possível iniciar a verificação enquanto assina");
			System.exit(1);
		}
		if (this.verifying) {
			System.err.println("Verificação já está ativa");
			System.exit(1);
		}

		System.out.println("Iniciando verificação da assinatura");
		this.signning = false;
		this.verifying = true;
		this.holder = chavePublica;
		this.buffer = ByteBuffer.allocate(2048);
	}

	public final Boolean verify(byte[] signature) {
		byte[] originalDigest = null;
		boolean result = false;
		try {
			this.cifra.init(Cipher.DECRYPT_MODE, holder);
			originalDigest = this.cifra.doFinal(signature);
		} catch (InvalidKeyException e) {
			System.err.println("Chave inválida na decriptação");
			System.exit(1);
		} catch (IllegalBlockSizeException e) {
			System.err.println("Erro no tamanho do bloco alocado na decriptação");
			System.exit(1);
		} catch (BadPaddingException e) {
			System.err.println("Erro no padding na decriptação");
			System.exit(1);
		}

		byte[] tempDigest = makeDigest(buffer.array(), 0, buffer.position());

		result = Arrays.equals(tempDigest, originalDigest);

		System.out.println("verificação da assinatura terminada");
		if (result) {
			System.out.println("Signature verified");
		} else {
			System.out.println("Signature failed");
		}

		buffer.clear();
		this.verifying = false;
		this.holder = null;

		return result;
	}

	public static String HexCodeString(byte[] hexCode) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < hexCode.length; i++) {
			String hex = Integer.toHexString(0x0100 + (hexCode[i] & 0x00FF)).substring(1);
			buf.append((hex.length() < 2 ? "0" : "") + hex);
		}
		return buf.toString();
	}
}
