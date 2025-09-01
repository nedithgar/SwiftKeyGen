# UTF8Span

**Structure**

> A borrowed view into contiguous memory that contains validly-encoded UTF-8 code units.

**Availability:**
* iOS 26.0+
* iPadOS 26.0+
* Mac Catalyst 26.0+
* macOS 26.0+
* tvOS 26.0+
* visionOS 26.0+
* watchOS 26.0+

```swift
@frozen struct UTF8Span
```

## Topics

### Structures

* `struct CharacterIterator Character UTF8Span`: struct CharacterIterator Iterate the Character contents of a UTF8Span.
* `struct UnicodeScalarIterator Unicode.Scalar UTF8Span`: struct UnicodeScalarIterator Iterate the Unicode.Scalars contents of a UTF8Span.

### Initializers

* `init(unchecked: Span<UInt8>, isKnownASCII: Bool) codeUnits isKnownASCII: true is passed`: init(unchecked: Span<UInt8>, isKnownASCII: Bool) Creates a UTF8Span, bypassing safety and security checks. The caller must guarantee that codeUnits contains validly-encoded UTF-8, or else undefined behavior may result upon use. If isKnownASCII: true is passed, the contents must be ASCII, or else undefined behavior may result upon use.
* `init(validating: consuming Span<UInt8>) throws(UTF8.ValidationError) codeUnits`: init(validating: consuming Span<UInt8>) throws(UTF8.ValidationError) Creates a UTF8Span containing codeUnits. Validates that the input is valid UTF-8, otherwise throws an error.

### Instance Properties

* `var count: Int`: The number of UTF-8 code units in the span.
* `var isEmpty: Bool`: A Boolean value that indicates whether the UTF-8 span is empty.
* `var isKnownASCII: Bool true false`: var isKnownASCII: Bool Returns whether contents are known to be all-ASCII. A return value of true means that all code units are ASCII. A return value of false means there may be non-ASCII content.
* `var isKnownNFC: Bool checkForNFC`: var isKnownNFC: Bool Returns whether the contents are known to be NFC. This is not always checked at initialization time and is set by checkForNFC.
* `var span: Span<UInt8>`: A span used to access the code units.

### Instance Methods

* `func bytesEqual(to: some Sequence<UInt8>) -> Bool other`: func bytesEqual(to: some Sequence<UInt8>) -> Bool Whether this span has the same bytes as other.
* `func charactersEqual(to: some Sequence<Character>) -> Bool Character other`: func charactersEqual(to: some Sequence<Character>) -> Bool Whether this span has the same Characters as other.
* `func checkForASCII() -> Bool`: Do a scan checking for whether the contents are all-ASCII.
* `func checkForNFC(quickCheck: Bool) -> Bool`: Do a scan checking for whether the contents are in Normal Form C. When the contents are in NFC, canonical equivalence checks are much faster.
* `func isCanonicallyEquivalent(to: UTF8Span) -> Bool self other`: func isCanonicallyEquivalent(to: UTF8Span) -> Bool Whether self is equivalent to other under Unicode Canonical Equivalence.
* `func isCanonicallyLessThan(UTF8Span) -> Bool self other`: func isCanonicallyLessThan(UTF8Span) -> Bool Whether self orders less than other under Unicode Canonical Equivalence using normalized code-unit order (in NFC).
* `func makeCharacterIterator() -> UTF8Span.CharacterIterator Character`: func makeCharacterIterator() -> UTF8Span.CharacterIterator Returns an iterator that will construct Characters from the underlying UTF-8 content.
* `func makeUnicodeScalarIterator() -> UTF8Span.UnicodeScalarIterator Unicode.Scalar`: func makeUnicodeScalarIterator() -> UTF8Span.UnicodeScalarIterator Returns an iterator that will decode the code units into Unicode.Scalars.
* `func unicodeScalarsEqual(to: some Sequence<Unicode.Scalar>) -> Bool Unicode.Scalar other`: func unicodeScalarsEqual(to: some Sequence<Unicode.Scalar>) -> Bool Whether this span has the same Unicode.Scalars as other.

## Relationships

### Conforms To

* `BitwiseCopyable`: 

## See Also

### Safe Memory Access

* `struct Span Span<Element> Element`: struct Span Span<Element> represents a contiguous region of memory which contains initialized instances of Element.
* `struct RawSpan RawSpan`: represents a contiguous region of memory which contains initialized bytes.
* `struct OutputSpan`: 
* `struct MutableSpan`: 
* `struct MutableRawSpan`: 

