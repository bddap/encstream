// helper function to configure a snow noise session

pub fn builder() -> snow::Builder<'static> {
    snow::Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("failed to parse noise protocol description"),
    )
}
