package aes;

public class AES {
	private static final int TAILLE_BLOC = 128; 
	private static final int[] Rcon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
	private static final int[] sBox = {
	        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	    };
	private static final int[] sBoxInv = {
	        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	    };
	
	//attributs class AES
	private int tailleCleMaitre;
    private int nbRonde;
    private int[][] masterKey;
    private int[][][] keys;
    
    //constructor class AES
    public AES(int tailleCleMaitre) {
        if (tailleCleMaitre != 128 && tailleCleMaitre != 192 && tailleCleMaitre != 256) {
            throw new IllegalArgumentException(
                "La taille de la clé doit être de 128, 192 ou 256 bits."
            );
        }

        this.tailleCleMaitre = tailleCleMaitre;
        switch (tailleCleMaitre) {
            case 192:
                this.nbRonde = 12;
                break;
            case 256:
                this.nbRonde = 14;
                break;
            default:
                this.nbRonde = 10;
        }
        this.genereMasterKey();
        this.createKeys();
    }

    //Method class AES
    private static int[] stringToBits(String message) {
        int[] tableauBits = new int[message.length() * 8];
        int index = 0;
        for (int i = 0; i < message.length(); i++) {
            int ascii = message.charAt(i);
            for (int j = 7; j >= 0; j--) {
                tableauBits[index++] = (ascii >> j) & 1;
            }
        }
        return tableauBits;
    }
    //Methode 1)
    private static String bitsToString(int[] blocs) {
        StringBuilder message = new StringBuilder();
        for (int i = 0; i < blocs.length; i += 8) {
            int valeurAscii = 0;

            for (int j = 0; j < 8; j++) {
                valeurAscii = valeurAscii * 2 + blocs[i + j];
            }
            message.append((char) valeurAscii);
        }
        return message.toString();
    }
    //Methode 2)
    private void genereMasterKey() {
        int nombreOctets = tailleCleMaitre / 8;

        masterKey = new int[nombreOctets][8];

        for (int i = 0; i < nombreOctets; i++) {
            int valeur = (int) (Math.random() * 256);

            for (int j = 7; j >= 0; j--) {
                masterKey[i][7 - j] = (valeur >> j) & 1;
            }
        }
    }
    //Methode 3)
    private void createKeys() {
    this.keys = new int[this.nbRonde + 1][16][8];
    int[][] w = new int[44][32];
    int indexOctet = 0;
    for (int i = 0; i < 4; i++) {
        int bitIdx = 0;
        for (int o = 0; o < 4; o++) {
            for (int b = 0; b < 8; b++) {
                w[i][bitIdx++] = this.masterKey[indexOctet][b];
            }
            indexOctet++;
        }
    }
    for (int i = 4; i < 44; i++) {
        int[] temp = w[i - 1].clone();
        
        if (i % 4 == 0) {
            int[] rotTemp = new int[32];
            System.arraycopy(temp, 8, rotTemp, 0, 24);
            System.arraycopy(temp, 0, rotTemp, 24, 8);
            temp = rotTemp;
            int[] subTemp = new int[32];
            for (int o = 0; o < 4; o++) {
                int valOctet = 0;
                for (int b = 0; b < 8; b++) {
                    valOctet = (valOctet << 1) | temp[o * 8 + b];
                }
                int sboxVal = sBox[valOctet];
                for (int b = 7; b >= 0; b--) {
                    subTemp[o * 8 + (7 - b)] = (sboxVal >> b) & 1;
                }
            }
            temp = subTemp;
            int rconVal = Rcon[(i / 4) - 1];
            int firstOctetVal = 0;
            for (int b = 0; b < 8; b++) {
                firstOctetVal = (firstOctetVal << 1) | temp[b];
            }
            firstOctetVal ^= rconVal;
            for (int b = 7; b >= 0; b--) {
                temp[7 - b] = (firstOctetVal >> b) & 1;
            }
        }
        for (int b = 0; b < 32; b++) {
            w[i][b] = w[i - 4][b] ^ temp[b];
        }
    }
    for (int ronde = 0; ronde <= this.nbRonde; ronde++) {
        int octetIdx = 0;
        for (int wordIdx = 0; wordIdx < 4; wordIdx++) {
            int currentWord = ronde * 4 + wordIdx;
            int bitIdx = 0;
            for (int o = 0; o < 4; o++) {
                for (int b = 0; b < 8; b++) {
                    this.keys[ronde][octetIdx][b] = w[currentWord][bitIdx++];
                }
                octetIdx++;
            }
        }
    }
    }
    //Methode 4)
    private static int[] bourrage(int[] blocs) {
        int reste = blocs.length % 128;
        int taillePadding = 128 - reste; 
        int[] resultat = new int[blocs.length + taillePadding];

        for (int i = 0; i < blocs.length; i++) {
            resultat[i] = blocs[i];
        }
        resultat[blocs.length] = 1;
        for (int i = blocs.length + 1; i < resultat.length; i++) {
            resultat[i] = 0;
        }
        return resultat;
    }
    //Methode 5)
    private static int[] debourrage(int[] blocs) {
    	int i = blocs.length - 1;
    	while (i >= 0 && blocs[i] == 0) {
    		i--;
    	}
    	int tailleOriginale = i; 
    
    	int[] resultat = new int[tailleOriginale];
    	for (int j = 0; j < tailleOriginale; j++) {
    		resultat[j] = blocs[j];
    	}
    	return resultat;
    }
    //Methode 6)
    private static int[][] decoupage_en_blocs(int[] messageBinaire) {
        if (messageBinaire.length % 128 != 0) {
            throw new IllegalArgumentException("Le message doit être bourré (multiple de 128 bits) avant le découpage.");
        }
        int nombreDeBlocs = messageBinaire.length / 128;
        int[][] blocs = new int[nombreDeBlocs][128];
        for (int i = 0; i < nombreDeBlocs; i++) {
            System.arraycopy(messageBinaire, i * 128, blocs[i], 0, 128);
        }
        return blocs;
    }
    //Methode 7)
    private static int[] recollage_des_blocs(int[][] blocs) {
        int nombreDeBlocs = blocs.length;
        int[] messageBinaire = new int[nombreDeBlocs * 128];
        for (int i = 0; i < nombreDeBlocs; i++) {
            System.arraycopy(blocs[i], 0, messageBinaire, i * 128, 128);
        }
        return messageBinaire;
    }
    //Methode 8)
    public static int[] xor(int[] tab1, int[] tab2) {
        if (tab1.length != tab2.length) {
            throw new IllegalArgumentException("Les deux tableaux doivent avoir exactement la même taille.");
        }
        int[] resultat = new int[tab1.length];
        for (int i = 0; i < tab1.length; i++) {
            resultat[i] = tab1[i] ^ tab2[i];
        }
        return resultat;
    }
    //Methode 9)
    private static int[] addRoundKey(int[] state, int[] roundKey) {
    	return xor(state, roundKey); 
    } 
    //Methode 10)
    private static void subByte(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                byte valeurActuelle = state[i][j];

                int indice = valeurActuelle & 0xFF;

                int valeurSBox = sBox[indice];

                state[i][j] = (byte) valeurSBox;
            }
        }
    }   
    //Methode 11)
    private static void subByteInv(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int indice = state[i][j] & 0xFF;
                state[i][j] = (byte) sBoxInv[indice];
            }
        }
    } 
    //Methode 12)
    private static void shiftRows(byte[][] state) {
        byte[] copy = new byte[4];

        copy[0] = state[1][1];
        copy[1] = state[1][2];
        copy[2] = state[1][3];
        copy[3] = state[1][0];
        System.arraycopy(copy, 0, state[1], 0, 4);

        copy[0] = state[2][2];
        copy[1] = state[2][3];
        copy[2] = state[2][0];
        copy[3] = state[2][1];
        System.arraycopy(copy, 0, state[2], 0, 4);

        copy[0] = state[3][3];
        copy[1] = state[3][0];
        copy[2] = state[3][1];
        copy[3] = state[3][2];
        System.arraycopy(copy, 0, state[3], 0, 4);
    }
    //Methode 13)
    private static void shiftRowsInv(byte[][] state) {
        byte[] copy = new byte[4];
        copy[0] = state[1][3];
        copy[1] = state[1][0];
        copy[2] = state[1][1];
        copy[3] = state[1][2];
        System.arraycopy(copy, 0, state[1], 0, 4);
        
        copy[0] = state[2][2];
        copy[1] = state[2][3];
        copy[2] = state[2][0];
        copy[3] = state[2][1];
        System.arraycopy(copy, 0, state[2], 0, 4);

        copy[0] = state[3][1];
        copy[1] = state[3][2];
        copy[2] = state[3][3];
        copy[3] = state[3][0];
        System.arraycopy(copy, 0, state[3], 0, 4);
    } 
    //Methode 14)
    private static byte deux_a(byte a) {
        if ((a & 0x80) != 0) {
            return (byte) ((a << 1) ^ 0x1B);
        } else {
            return (byte) (a << 1);
        }
    }    
    //Methode 15)
    private static byte trois_a(byte a) {
        return (byte) (deux_a(a) ^ a);
    } 
    //Methode 16)
    private static byte neuf_a(byte a) {
        return (byte) (deux_a(deux_a(deux_a(a))) ^ a);
    }
    //Methode 17)
    private static byte onze_a(byte a) {
        byte double_a = deux_a(a);
        return (byte) (deux_a(deux_a(double_a)) ^ double_a ^ a);
    }
    //Methode 18)
    private static byte treize_a(byte a) {
        byte quadruple_a = deux_a(deux_a(a));
        return (byte) (deux_a(quadruple_a) ^ quadruple_a ^ a);
    }
    //Methode 19)
    private static byte quatorze_a(byte a) {
        byte double_a = deux_a(a);
        byte quadruple_a = deux_a(double_a);
        return (byte) (deux_a(quadruple_a) ^ quadruple_a ^ double_a);
    }
    //Methode 20)
    private static byte[] prodAu(byte[] col) {
        byte[] result = new byte[4];
        
        result[0] = (byte) (deux_a(col[0]) ^ trois_a(col[1]) ^ col[2] ^ col[3]);
        result[1] = (byte) (col[0] ^ deux_a(col[1]) ^ trois_a(col[2]) ^ col[3]);
        result[2] = (byte) (col[0] ^ col[1] ^ deux_a(col[2]) ^ trois_a(col[3]));
        result[3] = (byte) (trois_a(col[0]) ^ col[1] ^ col[2] ^ deux_a(col[3]));
        
        return result;
    }
    //Methode 21)
    private static byte[] prodAuInv(byte[] col) {
        byte[] result = new byte[4];
        
        result[0] = (byte) (quatorze_a(col[0]) ^ onze_a(col[1]) ^ treize_a(col[2]) ^ neuf_a(col[3]));
        result[1] = (byte) (neuf_a(col[0]) ^ quatorze_a(col[1]) ^ onze_a(col[2]) ^ treize_a(col[3]));
        result[2] = (byte) (treize_a(col[0]) ^ neuf_a(col[1]) ^ quatorze_a(col[2]) ^ onze_a(col[3]));
        result[3] = (byte) (onze_a(col[0]) ^ treize_a(col[1]) ^ neuf_a(col[2]) ^ quatorze_a(col[3]));
        
        return result;
    }
    //Methode 22)
    private static void mixColumns(byte[][] state) {
        for (int j = 0; j < 4; j++) {
            byte[] col = new byte[4];
            for (int i = 0; i < 4; i++) {
                col[i] = state[i][j];
            }
            byte[] newCol = prodAu(col);

            for (int i = 0; i < 4; i++) {
                state[i][j] = newCol[i];
            }
        }
    }
    //Methode 23)
    public int[] crypte(String message) {
    int[] bits = stringToBits(message);
    int[] bitsBourres = bourrage(bits);
    int[][] blocs = decoupage_en_blocs(bitsBourres);
    int[][] blocsChiffres = new int[blocs.length][128];
    
    for (int b = 0; b < blocs.length; b++) {
        int[] blocActuel = blocs[b].clone();
        int[] roundKeyFlat = new int[128];
        int kIdx = 0;
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 8; j++) {
                roundKeyFlat[kIdx++] = this.keys[0][i][j];
            }
        }
        blocActuel = addRoundKey(blocActuel, roundKeyFlat);
        byte[][] state = new byte[4][4];
        int idxBit = 0;
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                int valeurOctet = 0;
                for (int k = 0; k < 8; k++) {
                    valeurOctet = (valeurOctet << 1) | blocActuel[idxBit++];
                }
                state[i][j] = (byte) valeurOctet;
            }
        }
        for (int ronde = 1; ronde < this.nbRonde; ronde++) {
            subByte(state);
            shiftRows(state);
            mixColumns(state);
            idxBit = 0;
            for (int j = 0; j < 4; j++) {
                for (int i = 0; i < 4; i++) {
                    int valeurOctet = state[i][j] & 0xFF;
                    for (int k = 7; k >= 0; k--) {
                        blocActuel[idxBit++] = (valeurOctet >> k) & 1;
                    }
                }
            }
            roundKeyFlat = new int[128];
            kIdx = 0;
            for (int i = 0; i < 16; i++) {
                for (int j = 0; j < 8; j++) {
                    roundKeyFlat[kIdx++] = this.keys[ronde][i][j];
                }
            }
            blocActuel = addRoundKey(blocActuel, roundKeyFlat); 
            idxBit = 0;
            for (int j = 0; j < 4; j++) {
                for (int i = 0; i < 4; i++) {
                    int valeurOctet = 0;
                    for (int k = 0; k < 8; k++) {
                        valeurOctet = (valeurOctet << 1) | blocActuel[idxBit++];
                    }
                    state[i][j] = (byte) valeurOctet;
                }
            }
        }
        subByte(state);
        shiftRows(state);
        idxBit = 0;
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                int valeurOctet = state[i][j] & 0xFF;
                for (int k = 7; k >= 0; k--) {
                    blocActuel[idxBit++] = (valeurOctet >> k) & 1;
                }
            }
        }
        roundKeyFlat = new int[128];
        kIdx = 0;
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 8; j++) {
                roundKeyFlat[kIdx++] = this.keys[this.nbRonde][i][j];
            }
        }
        blocActuel = addRoundKey(blocActuel, roundKeyFlat); 
        
        blocsChiffres[b] = blocActuel;
    }
    
    return recollage_des_blocs(blocsChiffres);
    }
    //Methode 24)
    public String decrypte(int[] messCode) {
        int[][] blocsChiffres = decoupage_en_blocs(messCode);
        int[][] blocsDechiffres = new int[blocsChiffres.length][128];
        
        for (int b = 0; b < blocsChiffres.length; b++) {
            int[] blocActuel = blocsChiffres[b].clone();
            int[] roundKeyFlat = new int[128];
            int kIdx = 0;
            for (int i = 0; i < 16; i++) {
                for (int j = 0; j < 8; j++) {
                    roundKeyFlat[kIdx++] = this.keys[this.nbRonde][i][j];
                }
            }
            blocActuel = addRoundKey(blocActuel, roundKeyFlat); 
            byte[][] state = new byte[4][4];
            int idxBit = 0;
            for (int j = 0; j < 4; j++) {
                for (int i = 0; i < 4; i++) {
                    int valeurOctet = 0;
                    for (int k = 0; k < 8; k++) {
                        valeurOctet = (valeurOctet << 1) | blocActuel[idxBit++];
                    }
                    state[i][j] = (byte) valeurOctet;
                }
            }
            shiftRowsInv(state);
            subByteInv(state);
            for (int ronde = this.nbRonde - 1; ronde >= 1; ronde--) {
                idxBit = 0;
                for (int j = 0; j < 4; j++) {
                    for (int i = 0; i < 4; i++) {
                        int valeurOctet = state[i][j] & 0xFF;
                        for (int k = 7; k >= 0; k--) {
                            blocActuel[idxBit++] = (valeurOctet >> k) & 1;
                        }
                    }
                }
                
                roundKeyFlat = new int[128];
                kIdx = 0;
                for (int i = 0; i < 16; i++) {
                    for (int j = 0; j < 8; j++) {
                        roundKeyFlat[kIdx++] = this.keys[ronde][i][j];
                    }
                }
                blocActuel = addRoundKey(blocActuel, roundKeyFlat); 
                idxBit = 0;
                for (int j = 0; j < 4; j++) {
                    for (int i = 0; i < 4; i++) {
                        int valeurOctet = 0;
                        for (int k = 0; k < 8; k++) {
                            valeurOctet = (valeurOctet << 1) | blocActuel[idxBit++];
                        }
                        state[i][j] = (byte) valeurOctet;
                    }
                }
                for (int j = 0; j < 4; j++) {
                    byte[] col = new byte[4];
                    for (int i = 0; i < 4; i++) {
                        col[i] = state[i][j];
                    }
                    byte[] newCol = prodAuInv(col);
                    for (int i = 0; i < 4; i++) {
                        state[i][j] = newCol[i];
                    }
                }
                shiftRowsInv(state);
                
                subByteInv(state);
            }

            idxBit = 0;
            for (int j = 0; j < 4; j++) {
                for (int i = 0; i < 4; i++) {
                    int valeurOctet = state[i][j] & 0xFF;
                    for (int k = 7; k >= 0; k--) {
                        blocActuel[idxBit++] = (valeurOctet >> k) & 1;
                    }
                }
            }
            
            roundKeyFlat = new int[128];
            kIdx = 0;
            for (int i = 0; i < 16; i++) {
                for (int j = 0; j < 8; j++) {
                    roundKeyFlat[kIdx++] = this.keys[0][i][j];
                }
            }
            blocActuel = addRoundKey(blocActuel, roundKeyFlat); 
            
            blocsDechiffres[b] = blocActuel;
        }
        
        int[] bitsBourres = recollage_des_blocs(blocsDechiffres);
        int[] bitsClairs = debourrage(bitsBourres);
        return bitsToString(bitsClairs);
    }

}
