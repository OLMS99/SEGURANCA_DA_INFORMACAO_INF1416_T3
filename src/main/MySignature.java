// -------------------------
// Jam Ajna Soares - 2211689 
// Olavo Lucas     - 1811181
// -------------------------

import java.util.*;

import java.security.*;
import javax.crypto.*;

public class MySignature {
	public static void main(String[] args){}

	//Padrões de assinatura suportados:
	//HashSet<String> padroesSuportadosAss = new HashSet<String>(Arrays.asList("MD5withRSA", "SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "SHA256withECDSA"));
	//campos para guardar [CriptografiaD]with[CriptografiaA]?
	//getInstance(String padraoAssinatura)
	//initSign
	//update
	//sign
	//initVerify
	//verify
	private static String HexCodeString(byte[] hexCode) {
		StringBuffer buf = new StringBuffer();

		for (int i = 0; i < hexCode.length; i++) {
			String hex = Integer.toHexString(0x0100 + (hexCode[i] & 0x00FF)).substring(1);
			buf.append((hex.length() < 2 ? "0" : "") + hex);
		}
		return buf.toString();
	}
}