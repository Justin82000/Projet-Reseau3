import org.junit.Test;

import aes.AES;

class TestAES {

    @Test
    void testAES128() {
        AES aes = new AES(128);
        String messageOriginal = "Test AES avec une clé de 128 bits";

        int[] crypte = aes.crypte(messageOriginal);
        String dechiffre = aes.decrypte(crypte);
        
        assertNotNull(crypte, "Le message chiffré ne doit pas être nul");
        assertEquals(messageOriginal, dechiffre, "Le message déchiffré doit être identique à l'original");
    }

    @Test
    void testAES192() {
        AES aes = new AES(192);
        String messageOriginal = "Message secret protégé en 192 bits !";

        int[] crypte = aes.crypte(messageOriginal);
        String dechiffre = aes.decrypte(crypte);
        
        assertNotNull(crypte, "Le message chiffré ne doit pas être nul");
        assertEquals(messageOriginal, dechiffre, "Le déchiffrement AES-192 a échoué");
    }

    @Test
    void testAES256() {
        AES aes = new AES(256);
        String messageOriginal = "Sécurité maximale avec AES 256 bits standard.";

        int[] crypte = aes.crypte(messageOriginal);
        String dechiffre = aes.decrypte(crypte);
        
        assertNotNull(crypte, "Le message chiffré ne doit pas être nul");
        assertEquals(messageOriginal, dechiffre, "Le déchiffrement AES-256 a échoué");
    }

    @Test
    void testTailleCleInvalide() {
        assertThrows(IllegalArgumentException.class, () -> new AES(64));
        assertThrows(IllegalArgumentException.class, () -> new AES(512));
    }
}
