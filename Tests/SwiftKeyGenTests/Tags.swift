import Testing

extension Tag {
    @Tag static var unit: Self
    @Tag static var integration: Self
    @Tag static var performance: Self
    @Tag static var critical: Self

    @Tag static var rsa: Self
    @Tag static var slow: Self
}