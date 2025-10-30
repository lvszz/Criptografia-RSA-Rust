use rsa::{
    RsaPrivateKey,
    RsaPublicKey,
    // Tipos de Preenchimento (Padding) para Criptografia
    Pkcs1v15Encrypt,
    errors::Result as RsaResult,
};
use rsa::traits::PublicKeyParts;
use rand::rngs::OsRng; // Gerador de Números Aleatórios seguro

fn main() -> RsaResult<()> {
    println!("--- Algoritmo RSA em Rust ---");

    // 1. Geração de Chaves
    println!("\n1. Gerando Par de Chaves (2048 bits)...");
    let mut rng = OsRng;
    let bits = 2048; 
    
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Falha ao gerar a chave privada");
        
    let public_key = RsaPublicKey::from(&private_key);

    println!("   Chaves geradas com sucesso!");
    println!("   Tamanho do Módulo (N): {} bytes", public_key.n().to_bytes_be().len());

    // 2. Criptografia de Mensagem
    let data = b"Esta e a minha mensagem secreta para criptografar.";
    println!("\n2. Mensagem Original: \"{}\"", String::from_utf8_lossy(data));
    
    let encrypted_data = public_key.encrypt(
        &mut rng,
        Pkcs1v15Encrypt,
        &data[..]
    )
    .expect("Falha ao criptografar");

    println!("   Mensagem Criptografada ({} bytes): {:?}", encrypted_data.len(), encrypted_data);
    
    // 3. Descriptografia de Mensagem
    let decrypted_data = private_key.decrypt(
        Pkcs1v15Encrypt,
        &encrypted_data
    )
    .expect("Falha ao descriptografar");

    let decrypted_message = String::from_utf8(decrypted_data)
        .expect("A mensagem descriptografada não é um texto UTF-8 válido");

    println!("\n3. Mensagem Descriptografada: \"{}\"", decrypted_message);

    assert_eq!(&data[..], decrypted_message.as_bytes());
    println!("\n✅ Sucesso: A mensagem original e a descriptografada são iguais!");

    Ok(())
}
