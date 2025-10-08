import Testing

extension Tag {
    @Tag static var unit: Self // Fast, focused tests of individual functions/types
    @Tag static var integration: Self // Multi-component tests (e.g., format conversion round-trips, CLI workflows)
    @Tag static var performance: Self
    @Tag static var critical: Self

    @Tag static var rsa: Self // RSA‑specific (often slower; may involve large BigInt operations)
    @Tag static var slow: Self // Explicitly > ~10s in Release (never run by default inner dev loop)
}